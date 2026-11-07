// Package docker reads the Docker Engine API from its unix socket.
//
// Environment variable values are never stored: they are scanned in memory to
// infer links between containers and then dropped.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	procnet "github.com/RavaliMeka/whatsrunning/internal/collector/ports"
	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

const maxResponse = 32 << 20

type Collector struct {
	socket string
	client *http.Client
}

func New(socket string) *Collector {
	if socket == "" {
		socket = "/var/run/docker.sock"
		if h, ok := strings.CutPrefix(os.Getenv("DOCKER_HOST"), "unix://"); ok {
			socket = h
		}
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	return &Collector{socket: socket, client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial}}}
}

func (c *Collector) Name() string { return "docker" }

func (c *Collector) Available() bool {
	st, err := os.Stat(c.socket)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func (c *Collector) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker API %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(out)
}

type binding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type container struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		Pid      int    `json:"Pid"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
	HostConfig struct {
		Privileged    bool                 `json:"Privileged"`
		NetworkMode   string               `json:"NetworkMode"`
		PidMode       string               `json:"PidMode"`
		PortBindings  map[string][]binding `json:"PortBindings"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports    map[string][]binding `json:"Ports"`
		Networks map[string]struct {
			Aliases   []string `json:"Aliases"`
			IPAddress string   `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type ref struct {
	node    *graph.Node
	env     []string
	project string
	service string
	deps    []string
}

func (c *Collector) Collect(ctx context.Context) (*graph.Graph, error) {
	g := graph.New()
	var ver struct{ Version string }
	if err := c.get(ctx, "/version", &ver); err != nil {
		return nil, fmt.Errorf("cannot reach Docker at %s (run as root or a docker group member): %w", c.socket, err)
	}
	g.Host.Docker = ver.Version

	var list []struct {
		ID string `json:"Id"`
	}
	if err := c.get(ctx, "/containers/json?all=1", &list); err != nil {
		return nil, err
	}
	used := map[string]bool{}
	var refs []*ref
	for _, l := range list {
		var ct container
		if err := c.get(ctx, "/containers/"+url.PathEscape(l.ID)+"/json", &ct); err != nil {
			g.Warnings = append(g.Warnings, err.Error())
			continue
		}
		refs = append(refs, addContainer(g, &ct, used))
	}

	var vols struct {
		Volumes []struct{ Name, Driver string }
	}
	if err := c.get(ctx, "/volumes", &vols); err != nil {
		g.Warnings = append(g.Warnings, err.Error())
	}
	for _, v := range vols.Volumes {
		if !used[v.Name] {
			g.AddNode(&graph.Node{ID: "vol:" + v.Name, Kind: graph.KindVolume, Name: volName(v.Name), Status: "unused",
				Attrs: map[string]string{"driver": v.Driver, "full_name": v.Name}})
		}
	}
	inferLinks(g, refs)
	return g, nil
}

func addContainer(g *graph.Graph, ct *container, used map[string]bool) *ref {
	name := strings.TrimPrefix(ct.Name, "/")
	project, service := ct.Config.Labels["com.docker.compose.project"], ct.Config.Labels["com.docker.compose.service"]
	user := ct.Config.User
	if user == "" {
		user = "root (default)"
	}
	restart := ct.HostConfig.RestartPolicy.Name
	if restart == "" {
		restart = "no"
	}
	n := g.AddNode(&graph.Node{ID: "ctr:" + name, Kind: graph.KindContainer, Name: name, Group: project, Status: ct.State.Status,
		Attrs: map[string]string{
			"id": ct.ID[:min(12, len(ct.ID))], "image": ct.Config.Image, "user": user, "restart": restart,
			"privileged": strconv.FormatBool(ct.HostConfig.Privileged), "network_mode": ct.HostConfig.NetworkMode,
			"pid_mode": ct.HostConfig.PidMode, "running": strconv.FormatBool(ct.State.Running),
			"exit_code": strconv.Itoa(ct.State.ExitCode), "compose_service": service,
		}})

	env := make([]string, 0, len(ct.Config.Env))
	for _, kv := range ct.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		n.Lists["env"] = append(n.Lists["env"], k)
		env = append(env, v)
	}

	// Stopped containers only report the bindings they would publish.
	ports := ct.NetworkSettings.Ports
	if !ct.State.Running {
		ports = ct.HostConfig.PortBindings
	}
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cport, _, _ := strings.Cut(k, "/")
		n.Lists["ports"] = append(n.Lists["ports"], cport)
		for _, b := range ports[k] {
			hp, _ := strconv.Atoi(b.HostPort)
			public := isPublic(b.HostIP)
			bind := b.HostIP
			if public && (bind == "" || bind == "::") {
				bind = "0.0.0.0"
			}
			pub := fmt.Sprintf("%s:%d -> %s", bind, hp, k)
			if slices.Contains(n.Lists["published"], pub) {
				continue // the same port is reported for IPv4 and IPv6
			}
			n.Lists["published"] = append(n.Lists["published"], pub)
			g.Expose(n.ID, hp, public, fmt.Sprintf("%s:%d→%s", bind, hp, cport))
		}
	}

	for _, m := range ct.Mounts {
		id, label, attrs := "", "", map[string]string{"type": m.Type}
		switch m.Type {
		case "volume":
			used[m.Name] = true
			id, label, attrs["full_name"] = "vol:"+m.Name, volName(m.Name), m.Name
		case "bind":
			id, label = "bind:"+m.Source, m.Source
		default:
			continue
		}
		mode := "ro"
		if m.RW {
			mode = "rw"
		}
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindVolume, Name: label, Status: "in use", Attrs: attrs})
		g.AddEdge(&graph.Edge{From: n.ID, To: id, Kind: graph.EdgeMounts, Label: m.Destination + " (" + mode + ")"})
		n.Lists["mounts"] = append(n.Lists["mounts"], fmt.Sprintf("%s -> %s (%s)", label, m.Destination, mode))
	}

	hostnames := []string{name, service}
	for nw, s := range ct.NetworkSettings.Networks {
		n.Lists["networks"] = append(n.Lists["networks"], nw)
		hostnames = append(hostnames, s.Aliases...)
		if s.IPAddress != "" {
			n.Lists["ips"] = append(n.Lists["ips"], s.IPAddress)
		}
	}
	sort.Strings(n.Lists["networks"])
	if ct.State.Running && ct.State.Pid > 0 && ct.HostConfig.NetworkMode != "host" {
		// Each container has its own network namespace, visible through any of its processes.
		n.Lists["connects"] = procnet.Outbound(fmt.Sprintf("/proc/%d/net", ct.State.Pid))
	}
	slices.Sort(hostnames)
	n.Lists["hostnames"] = slices.DeleteFunc(slices.Compact(hostnames), func(h string) bool { return len(h) < 2 || hexID.MatchString(h) })

	var deps []string
	for _, d := range strings.Split(ct.Config.Labels["com.docker.compose.depends_on"], ",") {
		if svc, _, _ := strings.Cut(d, ":"); svc != "" {
			deps = append(deps, svc)
		}
	}
	return &ref{node: n, env: env, project: project, service: service, deps: deps}
}

var (
	token = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_.-]*`)
	hexID = regexp.MustCompile(`^[0-9a-f]{12,}$`)
)

// inferLinks draws "A talks to B" from compose depends_on and from env values that
// name another container (DATABASE_URL=postgres://db:5432 -> db).
func inferLinks(g *graph.Graph, refs []*ref) {
	byHost := map[string]*ref{}
	for _, r := range refs {
		for _, h := range r.node.Lists["hostnames"] {
			if _, taken := byHost[h]; !taken {
				byHost[h] = r
			}
		}
	}
	link := func(a, b *ref, why string) {
		if a != b && sharesNetwork(a.node, b.node) {
			g.AddEdge(&graph.Edge{From: a.node.ID, To: b.node.ID, Kind: graph.EdgeTalksTo, Label: why})
		}
	}
	for _, r := range refs {
		for _, o := range refs {
			if o.project == r.project && slices.Contains(r.deps, o.service) {
				link(r, o, "depends_on")
			}
		}
		for _, v := range r.env {
			for _, t := range token.FindAllString(v, -1) {
				if o, ok := byHost[t]; ok && !hasLink(g, r.node.ID, o.node.ID) {
					link(r, o, "env reference")
				}
			}
		}
		r.env = nil
	}
}

func hasLink(g *graph.Graph, from, to string) bool {
	for _, e := range g.EdgesTo(to, graph.EdgeTalksTo) {
		if e.From == from {
			return true
		}
	}
	return false
}

func sharesNetwork(a, b *graph.Node) bool {
	if a.Attrs["network_mode"] == "host" || b.Attrs["network_mode"] == "host" {
		return true
	}
	return slices.ContainsFunc(a.Lists["networks"], func(n string) bool { return slices.Contains(b.Lists["networks"], n) })
}

func isPublic(ip string) bool {
	if ip == "" {
		return true
	}
	p := net.ParseIP(strings.Trim(ip, "[]"))
	return p != nil && !p.IsLoopback()
}

func volName(name string) string {
	if len(name) == 64 && hexID.MatchString(name) {
		return "anonymous:" + name[:12]
	}
	return name
}
