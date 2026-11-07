// Package remote scans other servers over SSH. It copies this binary to a
// private temporary file on the server, runs a scan there, reads the JSON
// result and removes the file. The system ssh client is used, so the user's
// ssh config, keys, agent, jump hosts and known_hosts all apply.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

const maxReport = 64 << 20

type Options struct {
	SSH  string // ssh client binary
	Self string // binary to run remotely; must match the server's OS and CPU
	Sudo bool   // run the remote scan with sudo -n
}

// A target is an ssh destination: host, user@host or an ssh_config alias.
// Anything else, notably a leading "-", could be read as an ssh option.
var validTarget = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@:-]{0,252}$`)

// script runs on the server. It is constant: no user input is interpolated.
const script = `umask 077; f=$(mktemp "$HOME/.whatsrunning.XXXXXXXX") || exit 1; trap 'rm -f "$f"' EXIT; cat > "$f" && chmod 700 "$f" && %s"$f" scan -o - -json -`

var arch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}

func Scan(ctx context.Context, target string, o Options) (*graph.Graph, error) {
	if !validTarget.MatchString(target) {
		return nil, fmt.Errorf("invalid ssh target %q", target)
	}
	if o.SSH == "" {
		o.SSH = "ssh"
	}
	uname, err := run(ctx, o.SSH, target, "uname -sm", nil)
	if err != nil {
		return nil, err
	}
	if want := "Linux " + arch[runtime.GOARCH]; strings.TrimSpace(string(uname)) != want {
		return nil, fmt.Errorf("%s runs %q, this binary is for %q; use a matching build", target, strings.TrimSpace(string(uname)), want)
	}

	bin, err := os.Open(o.Self)
	if err != nil {
		return nil, err
	}
	defer bin.Close()
	sudo := ""
	if o.Sudo {
		sudo = "sudo -n "
	}
	out, err := run(ctx, o.SSH, target, fmt.Sprintf(script, sudo), bin)
	if err != nil {
		return nil, err
	}
	var rep struct{ Graph *graph.Graph }
	if err := json.Unmarshal(out, &rep); err != nil || rep.Graph == nil {
		return nil, fmt.Errorf("%s: unreadable scan result: %v", target, err)
	}
	return rep.Graph, nil
}

func run(ctx context.Context, sshBin, target, command string, stdin io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, sshBin, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "--", target, command)
	cmd.Stdin = stdin
	var stdout, stderr limited
	stdout.max, stderr.max = maxReport, 4096
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", target, msg)
	}
	if stdout.over {
		return nil, fmt.Errorf("%s: scan result larger than %d bytes", target, maxReport)
	}
	return stdout.Bytes(), nil
}

// limited is a buffer that stops growing at max bytes.
type limited struct {
	bytes.Buffer
	max  int
	over bool
}

// Write discards what does not fit but reports it consumed, so the copy goroutine
// keeps draining the pipe instead of failing with a short write.
func (l *limited) Write(p []byte) (int, error) {
	n := len(p)
	if room := l.max - l.Len(); n > room {
		l.over = true
		p = p[:max(room, 0)]
	}
	l.Buffer.Write(p)
	return n, nil
}
