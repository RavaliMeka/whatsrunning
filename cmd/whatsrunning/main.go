package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/RavaliMeka/whatsrunning/internal/collector"
	"github.com/RavaliMeka/whatsrunning/internal/collector/docker"
	"github.com/RavaliMeka/whatsrunning/internal/collector/ports"
	"github.com/RavaliMeka/whatsrunning/internal/demo"
	"github.com/RavaliMeka/whatsrunning/internal/graph"
	"github.com/RavaliMeka/whatsrunning/internal/remote"
	"github.com/RavaliMeka/whatsrunning/internal/render"
	"github.com/RavaliMeka/whatsrunning/internal/rules"
	"github.com/RavaliMeka/whatsrunning/internal/scan"
)

var version = "dev"

const usage = `whatsrunning: see what is really running on a server, how it connects, and what is risky.

Usage:
  whatsrunning [scan] [flags]   scan this machine (default)
  whatsrunning demo  [flags]    map a sample server
  whatsrunning version

Flags:
  -o FILE              HTML map output (default "whatsrunning.html", "-" to skip)
  -json FILE           also write graph and findings as JSON ("-" for stdout)
  -docker-socket PATH  Docker socket (default /var/run/docker.sock or $DOCKER_HOST)
  -no-docker           skip Docker
  -no-ports            skip host listening ports
  -v                   also print low-severity findings
  -fail-on SEVERITY    exit 2 if any finding is at least SEVERITY (critical|high|medium|low)
  -ssh TARGET          scan a server over ssh (user@host or an ssh_config alias); repeatable
  -ssh-sudo            run remote scans with sudo -n
  -local               with -ssh, also scan this machine

Local scans send nothing anywhere. With -ssh, this binary is copied to a private
temporary file on each server, run, and deleted. Environment variable values are never recorded.
`

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "whatsrunning:", err)
		code = 1
	}
	os.Exit(code)
}

// run returns exit code 2 when -fail-on matches a finding.
func run(args []string) (int, error) {
	cmd := "scan"
	if len(args) > 0 && (args[0] == "scan" || args[0] == "demo" || args[0] == "version") {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println("whatsrunning", version)
		return 0, nil
	}

	fs := flag.NewFlagSet("whatsrunning", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	out := fs.String("o", "whatsrunning.html", "")
	jsonOut := fs.String("json", "", "")
	sock := fs.String("docker-socket", "", "")
	noDocker := fs.Bool("no-docker", false, "")
	noPorts := fs.Bool("no-ports", false, "")
	verbose := fs.Bool("v", false, "")
	failOn := fs.String("fail-on", "", "")
	var targets []string
	fs.Func("ssh", "", func(t string) error { targets = append(targets, t); return nil })
	sshSudo := fs.Bool("ssh-sudo", false, "")
	local := fs.Bool("local", false, "")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0, nil
	} else if err != nil {
		return 1, err
	}
	if *failOn != "" && rules.Rank(rules.Severity(*failOn)) > rules.Rank(rules.Low) {
		return 1, fmt.Errorf("-fail-on must be critical, high, medium or low")
	}

	var g *graph.Graph
	if cmd == "demo" {
		g = demo.Graph()
	} else {
		var cs []collector.Collector
		if !*noDocker {
			cs = append(cs, docker.New(*sock))
		}
		if !*noPorts {
			cs = append(cs, ports.New())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if len(targets) == 0 {
			g = scan.Run(ctx, cs)
		} else {
			var err error
			if g, err = scanServers(ctx, targets, *sshSudo, *local, cs); err != nil {
				return 1, err
			}
		}
	}
	rep := render.Report{Graph: g, Findings: rules.Evaluate(g)}

	if *jsonOut == "-" {
		if err := render.JSON(os.Stdout, rep); err != nil {
			return 1, err
		}
	} else {
		render.Terminal(os.Stdout, rep, render.UseColor(), *verbose)
		if *jsonOut != "" {
			if err := writeFile(*jsonOut, func(w io.Writer) error { return render.JSON(w, rep) }); err != nil {
				return 1, err
			}
			fmt.Printf("  JSON written to %s\n", *jsonOut)
		}
	}
	if *out != "-" {
		if err := writeFile(*out, func(w io.Writer) error { return render.HTML(w, rep) }); err != nil {
			return 1, err
		}
		if *jsonOut != "-" {
			abs, _ := filepath.Abs(*out)
			fmt.Printf("  Map written to %s\n\n", abs)
		}
	}

	if *failOn != "" {
		for _, f := range rep.Findings {
			if rules.Rank(f.Severity) <= rules.Rank(rules.Severity(*failOn)) {
				return 2, nil
			}
		}
	}
	return 0, nil
}

// scanServers scans each ssh target in parallel and merges them into one map.
// A failed server becomes a warning, unless every server failed.
func scanServers(ctx context.Context, targets []string, sudo, local bool, cs []collector.Collector) (*graph.Graph, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	parts := make([]scan.Part, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fmt.Fprintf(os.Stderr, "  scanning %s over ssh\n", t)
			g, err := remote.Scan(ctx, t, remote.Options{Self: self, Sudo: sudo})
			parts[i], errs[i] = scan.Part{Target: t, Graph: g}, err
		}()
	}
	var mine *graph.Graph
	if local {
		mine = scan.Run(ctx, cs)
	}
	wg.Wait()

	var ok []scan.Part
	if mine != nil {
		ok = append(ok, scan.Part{Target: "local", Graph: mine})
	}
	var warnings []string
	for i, p := range parts {
		if errs[i] != nil {
			warnings = append(warnings, errs[i].Error())
			continue
		}
		ok = append(ok, p)
	}
	if len(ok) == 0 {
		return nil, errors.Join(errs...)
	}
	g := scan.Combine(ok)
	g.Warnings = append(g.Warnings, warnings...)
	return g, nil
}

// writeFile creates the report readable by its owner only and refuses to follow
// a symlink: it usually runs as root, and the report maps the attack surface.
func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := fn(f); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}
