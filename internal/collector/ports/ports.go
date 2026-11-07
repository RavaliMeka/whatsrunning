// Package ports lists TCP listeners from /proc/net/tcp{,6} and maps each socket
// to its process through /proc/<pid>/fd.
package ports

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

type Collector struct{ proc string }

func New() *Collector { return &Collector{proc: "/proc"} }

func (c *Collector) Name() string { return "ports" }

func (c *Collector) Available() bool {
	_, err := os.Stat(filepath.Join(c.proc, "net/tcp"))
	return err == nil
}

type socket struct {
	ip, rip     net.IP
	port, rport int
	listen      bool
	inode       string
}

type proc struct {
	pid       int
	comm      string
	cmdline   string
	container string
}

func (c *Collector) Collect(context.Context) (*graph.Graph, error) {
	g := graph.New()
	socks, err := readSockets(filepath.Join(c.proc, "net"))
	if err != nil {
		g.Warnings = append(g.Warnings, err.Error())
	}
	owners, complete := c.socketOwners()
	if !complete {
		g.Warnings = append(g.Warnings, "ports: some processes were not readable; run as root to name them all")
	}

	for _, l := range socks {
		p := owners[l.inode]
		if !l.listen || (p != nil && p.comm == "docker-proxy") {
			continue // docker-proxy is represented by the container it forwards to
		}
		id, name := fmt.Sprintf("proc:unknown:%d", l.port), fmt.Sprintf("unknown process (:%d)", l.port)
		if p != nil {
			id, name = "proc:"+p.comm, p.comm
		}
		n := g.AddNode(&graph.Node{ID: id, Kind: graph.KindProcess, Name: name, Status: "listening"})
		if p != nil {
			n.Attrs["cmdline"] = p.cmdline
			if p.container != "" {
				n.Attrs["container_id"] = p.container
			}
		}
		bind := l.ip.String()
		if l.ip.IsUnspecified() {
			bind = "0.0.0.0"
		}
		addr := fmt.Sprintf("%s:%d", bind, l.port)
		if slices.Contains(n.Lists["listening"], addr) {
			continue
		}
		n.Lists["listening"] = append(n.Lists["listening"], addr)
		if port := strconv.Itoa(l.port); !slices.Contains(n.Lists["ports"], port) {
			n.Lists["ports"] = append(n.Lists["ports"], port)
		}
		g.Expose(id, l.port, !l.ip.IsLoopback(), addr)
	}

	// Outbound connections of the services found above become observed links.
	for _, s := range outbound(socks) {
		if p := owners[s.inode]; p != nil {
			if n := g.Node("proc:" + p.comm); n != nil {
				addConnect(n, s)
			}
		}
	}
	return g, nil
}

// Outbound lists "ip:port" peers of established connections that this network
// namespace opened (not inbound ones to its own listeners). dir is a /proc/<pid>/net path.
func Outbound(dir string) []string {
	socks, _ := readSockets(dir)
	n := &graph.Node{Lists: map[string][]string{}}
	for _, s := range outbound(socks) {
		addConnect(n, s)
	}
	return n.Lists["connects"]
}

func outbound(socks []socket) []socket {
	listening := map[int]bool{}
	for _, s := range socks {
		if s.listen {
			listening[s.port] = true
		}
	}
	var out []socket
	for _, s := range socks {
		if !s.listen && s.rip != nil && !s.rip.IsLoopback() && !listening[s.port] {
			out = append(out, s)
		}
	}
	return out
}

func addConnect(n *graph.Node, s socket) {
	if peer := net.JoinHostPort(s.rip.String(), strconv.Itoa(s.rport)); !slices.Contains(n.Lists["connects"], peer) {
		n.Lists["connects"] = append(n.Lists["connects"], peer)
	}
}

// readSockets parses tcp and tcp6 in a /proc net directory, keeping
// listening (0A) and established (01) sockets.
func readSockets(dir string) ([]socket, error) {
	var out []socket
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return out, err
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines[min(1, len(lines)):] { // skip the header
			fs := strings.Fields(line)
			if len(fs) < 10 || (fs[3] != "0A" && fs[3] != "01") {
				continue
			}
			ip, port, err1 := parseAddr(fs[1])
			rip, rport, err2 := parseAddr(fs[2])
			if err1 == nil && err2 == nil {
				s := socket{ip: ip, port: port, listen: fs[3] == "0A", inode: fs[9]}
				if !s.listen {
					s.rip, s.rport = rip, rport
				}
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// parseAddr decodes "0100007F:0035". The kernel prints each 32-bit word of the
// address in host (little-endian) byte order.
func parseAddr(s string) (net.IP, int, error) {
	h, p, _ := strings.Cut(s, ":")
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, int(port), nil
}

var (
	socketLink = regexp.MustCompile(`^socket:\[(\d+)\]$`)
	cgroupID   = regexp.MustCompile(`(?:docker[-/]|/containerd/|cri-containerd-|libpod-)([0-9a-f]{64})`)
)

// socketOwners maps socket inode to process; complete is false if any process was unreadable.
func (c *Collector) socketOwners() (map[string]*proc, bool) {
	out := map[string]*proc{}
	entries, err := os.ReadDir(c.proc)
	if err != nil {
		return out, false
	}
	complete := true
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(c.proc, e.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			complete = false
			continue
		}
		var p *proc
		for _, fd := range fds {
			link, _ := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			m := socketLink.FindStringSubmatch(link)
			if m == nil {
				continue
			}
			if p == nil {
				p = readProc(dir, pid)
			}
			if _, ok := out[m[1]]; !ok {
				out[m[1]] = p
			}
		}
	}
	return out, complete
}

func readProc(dir string, pid int) *proc {
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b))
	}
	p := &proc{pid: pid, comm: read("comm"), cmdline: redact(strings.ReplaceAll(read("cmdline"), "\x00", " "))}
	if m := cgroupID.FindStringSubmatch(read("cgroup")); m != nil {
		p.container = m[1]
	}
	return p
}

var (
	secretArg = regexp.MustCompile(`(?i)([a-z_-]*(?:pass|secret|token|key)[a-z_-]*[= ])\S+`)
	urlCreds  = regexp.MustCompile(`(://[^/\s:@]+:)[^@\s]+@`)
)

// redact strips likely secrets from a command line before it is stored.
func redact(s string) string {
	s = secretArg.ReplaceAllString(urlCreds.ReplaceAllString(s, "${1}***@"), "${1}***")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
