package nginx

import (
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

const confPath = "/etc/nginx/nginx.conf"

// instance is one running nginx and how to read its files from the host.
type instance struct {
	node    *graph.Node
	resolve func(string) (string, bool)
}

// Enrich adds domain nodes and routes for every nginx found in g. root is
// prepended to host paths (tests point it at a fixture directory).
func Enrich(g *graph.Graph, root string) {
	for _, in := range instances(g, root) {
		l := &loader{resolve: in.resolve, prefix: "/etc/nginx"}
		ds, err := l.load(confPath, 0)
		if err != nil && in.node.Kind == graph.KindContainer {
			// Images ship their own nginx.conf; a mounted conf.d is the usual setup.
			ds, err = l.include("conf.d/*.conf", 0), nil
		}
		if err != nil {
			g.Warnings = append(g.Warnings, err.Error())
			continue
		}
		addDomains(g, in.node, ds)
	}
}

func instances(g *graph.Graph, root string) []instance {
	var out []instance
	if n := g.Node("proc:nginx"); n != nil {
		out = append(out, instance{n, func(p string) (string, bool) { return filepath.Join(root, p), true }})
	}
	for _, n := range g.NodesOf(graph.KindContainer) {
		img := strings.ToLower(n.Attrs["image"])
		if n.Attrs["running"] != "true" || !(strings.Contains(img, "nginx") || strings.Contains(img, "openresty")) {
			continue
		}
		mounts := map[string]string{} // path in container -> path on host
		for _, e := range g.Edges {
			if e.From == n.ID && e.Kind == graph.EdgeMounts && strings.HasPrefix(e.To, "bind:") {
				dst, _, _ := strings.Cut(e.Label, " (")
				mounts[dst] = strings.TrimPrefix(e.To, "bind:")
			}
		}
		out = append(out, instance{n, func(p string) (string, bool) {
			best := ""
			for dst := range mounts {
				if (p == dst || strings.HasPrefix(p, strings.TrimSuffix(dst, "/")+"/")) && len(dst) > len(best) {
					best = dst
				}
			}
			if best == "" {
				return "", false
			}
			return filepath.Join(root, mounts[best], strings.TrimPrefix(p, best)), true
		}})
	}
	return out
}

type site struct {
	tls, plainServes bool
	ports            []string
	routes           [][2]string // location, target
}

func addDomains(g *graph.Graph, nginxNode *graph.Node, ds []directive) {
	upstreams := map[string][]string{}
	walk(ds, func(d directive) {
		if d.name == "upstream" && len(d.args) == 1 {
			for _, s := range d.block {
				if s.name == "server" && len(s.args) > 0 {
					upstreams[d.args[0]] = append(upstreams[d.args[0]], s.args[0])
				}
			}
		}
	})

	sites := map[string]*site{}
	var names []string
	walk(ds, func(d directive) {
		if d.name != "server" || d.block == nil {
			return
		}
		ports, ssl := listenPorts(d.block)
		var serverNames []string
		redirects := false
		var routes [][2]string
		for _, c := range d.block {
			switch c.name {
			case "server_name":
				serverNames = append(serverNames, c.args...)
			case "ssl_certificate":
				ssl = true
			case "return":
				redirects = redirects || isHTTPSRedirect(c.args)
			case "location":
				routes = append(routes, locationRoutes(c)...)
			}
		}
		serverNames = slices.DeleteFunc(serverNames, func(s string) bool { return s == "_" || s == "" || s == "localhost" })
		if len(serverNames) == 0 {
			serverNames = []string{"default (:" + strings.Join(ports, ",") + ")"}
		}
		for _, name := range serverNames {
			s := sites[name]
			if s == nil {
				s = &site{}
				sites[name] = s
				names = append(names, name)
			}
			s.tls = s.tls || ssl
			s.plainServes = s.plainServes || (!ssl && !redirects && len(routes) > 0)
			for _, p := range ports {
				if !slices.Contains(s.ports, p) {
					s.ports = append(s.ports, p)
				}
			}
			s.routes = append(s.routes, routes...)
		}
	})

	sort.Strings(names)
	for _, name := range names {
		s := sites[name]
		id := "domain:" + name
		d := g.AddNode(&graph.Node{ID: id, Kind: graph.KindDomain, Name: name, Status: "nginx",
			Attrs: map[string]string{"served_by": nginxNode.Name, "tls": strconv.FormatBool(s.tls), "plain_http_serves": strconv.FormatBool(s.plainServes)}})
		d.Lists["listen"] = s.ports
		for _, p := range s.ports {
			if hp := publicPort(g, nginxNode, p); hp > 0 {
				g.Expose(id, hp, true, ":"+strconv.Itoa(hp))
			}
		}
		for _, r := range s.routes {
			targets := []string{r[1]}
			if hosts, ok := upstreams[upstreamName(r[1])]; ok {
				targets = hosts
			}
			for _, t := range targets {
				d.Lists["routes"] = append(d.Lists["routes"], r[0]+" -> "+t)
				if to := resolve(g, nginxNode, t); to != nil {
					g.AddEdge(&graph.Edge{From: id, To: to.ID, Kind: graph.EdgeRoutes, Label: r[0]})
				} else if !strings.Contains(t, "$") {
					d.Lists["unresolved"] = append(d.Lists["unresolved"], r[0]+" -> "+t)
				}
			}
		}
	}
}

func listenPorts(block []directive) (ports []string, ssl bool) {
	for _, c := range block {
		if c.name != "listen" || len(c.args) == 0 {
			continue
		}
		addr := c.args[0]
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[i+1:]
		}
		if _, err := strconv.Atoi(addr); err == nil && !slices.Contains(ports, addr) {
			ports = append(ports, addr)
		}
		ssl = ssl || slices.Contains(c.args[1:], "ssl") || slices.Contains(c.args[1:], "quic")
	}
	if len(ports) == 0 {
		ports = []string{"80"}
	}
	return ports, ssl
}

func isHTTPSRedirect(args []string) bool {
	return len(args) == 2 && slices.Contains([]string{"301", "302", "307", "308"}, args[0]) && strings.HasPrefix(args[1], "https://")
}

// locationRoutes returns (path, upstream) for each proxy-style pass in a location.
func locationRoutes(loc directive) [][2]string {
	path := "/"
	if len(loc.args) > 0 {
		path = loc.args[len(loc.args)-1]
	}
	var out [][2]string
	for _, c := range loc.block {
		switch c.name {
		case "proxy_pass", "grpc_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass":
			if len(c.args) > 0 {
				out = append(out, [2]string{path, c.args[0]})
			}
		case "location":
			out = append(out, locationRoutes(c)...)
		}
	}
	return out
}

func upstreamName(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return target
}

// hostPort splits a pass target ("http://web:3000/x", "unix:/sock", "127.0.0.1:9000").
func hostPort(target string) (string, int) {
	if !strings.Contains(target, "://") {
		target = "tcp://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "unix" || u.Host == "" {
		return "", 0
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = map[string]int{"https": 443, "grpcs": 443}[u.Scheme]
		if port == 0 {
			port = 80
		}
	}
	return u.Hostname(), port
}

// resolve finds the node a pass target reaches, from where nginx runs.
func resolve(g *graph.Graph, from *graph.Node, target string) *graph.Node {
	host, port := hostPort(target)
	if host == "" {
		return nil
	}
	p := strconv.Itoa(port)
	inContainer := from.Kind == graph.KindContainer
	ip := net.ParseIP(host)
	hostSide := (!inContainer && (host == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())))) ||
		host == "host.docker.internal" || (inContainer && ip != nil && ip.Equal(net.IPv4(172, 17, 0, 1)))
	if hostSide {
		for _, e := range g.Edges {
			if e.Kind == graph.EdgeExposes && e.Port == port && e.To != from.ID && !strings.HasPrefix(e.To, "domain:") {
				return g.Node(e.To)
			}
		}
		return nil
	}
	for _, n := range g.NodesOf(graph.KindContainer) {
		if n == from || !slices.Contains(n.Lists["ports"], p) && len(n.Lists["ports"]) > 0 {
			continue
		}
		if slices.Contains(n.Lists["hostnames"], host) || slices.Contains(n.Lists["ips"], host) {
			return n
		}
	}
	return nil
}

// publicPort is the host port through which nginx's listen port is reachable
// from outside, or 0. A container's listen port may be published on another port.
func publicPort(g *graph.Graph, n *graph.Node, listen string) int {
	want, _ := strconv.Atoi(listen)
	if n.Kind == graph.KindContainer {
		want = 0
		for _, pub := range n.Lists["published"] {
			hostSide, ctr, _ := strings.Cut(pub, " -> ")
			if strings.TrimSuffix(strings.TrimSuffix(ctr, "/tcp"), "/udp") == listen {
				want, _ = strconv.Atoi(hostSide[strings.LastIndex(hostSide, ":")+1:])
				break
			}
		}
	}
	for _, e := range g.EdgesTo(n.ID, graph.EdgeExposes) {
		if e.Port == want && e.Public {
			return want
		}
	}
	return 0
}
