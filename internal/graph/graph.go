// Package graph is the model every collector writes into and every renderer reads.
package graph

import (
	"net"
	"sort"
	"strconv"
	"time"
)

type Kind string

const (
	KindEntry     Kind = "internet" // internet or localhost
	KindContainer Kind = "container"
	KindProcess   Kind = "process"
	KindVolume    Kind = "volume"
	KindDomain    Kind = "domain"
)

type EdgeKind string

const (
	EdgeExposes EdgeKind = "exposes"
	EdgeMounts  EdgeKind = "mounts"
	EdgeTalksTo EdgeKind = "talks-to"
	EdgeRoutes  EdgeKind = "routes" // domain -> service, from reverse proxy config
)

type Node struct {
	ID     string              `json:"id"`
	Kind   Kind                `json:"kind"`
	Name   string              `json:"name"`
	Group  string              `json:"group,omitempty"`
	Server string              `json:"server,omitempty"`
	Status string              `json:"status,omitempty"`
	Attrs  map[string]string   `json:"attrs,omitempty"`
	Lists  map[string][]string `json:"lists,omitempty"`
}

type Edge struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Kind   EdgeKind `json:"kind"`
	Label  string   `json:"label,omitempty"`
	Port   int      `json:"port,omitempty"`
	Public bool     `json:"public,omitempty"`
}

type HostInfo struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os,omitempty"`
	Docker    string    `json:"docker,omitempty"`
	Addrs     []string  `json:"addrs,omitempty"`
	ScannedAt time.Time `json:"scannedAt"`
}

type Graph struct {
	Host     HostInfo   `json:"host"`
	Servers  []HostInfo `json:"servers,omitempty"`
	Nodes    []*Node    `json:"nodes"`
	Edges    []*Edge    `json:"edges"`
	Warnings []string   `json:"warnings,omitempty"`
	index    map[string]*Node
	edges    map[Edge]bool
}

func New() *Graph {
	return &Graph{index: map[string]*Node{}, edges: map[Edge]bool{}}
}

// AddNode inserts n, or returns the node that already has n.ID.
func (g *Graph) AddNode(n *Node) *Node {
	if ex, ok := g.index[n.ID]; ok {
		return ex
	}
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	if n.Lists == nil {
		n.Lists = map[string][]string{}
	}
	g.index[n.ID] = n
	g.Nodes = append(g.Nodes, n)
	return n
}

func (g *Graph) AddEdge(e *Edge) {
	if !g.edges[*e] {
		g.edges[*e] = true
		g.Edges = append(g.Edges, e)
	}
}

// Expose links the internet (public) or localhost to a service listening on port.
func (g *Graph) Expose(to string, port int, public bool, label string) {
	from, name := "host", "This server (localhost only)"
	if public {
		from, name = "internet", "Internet / LAN"
	}
	g.AddNode(&Node{ID: from, Kind: KindEntry, Name: name})
	g.AddEdge(&Edge{From: from, To: to, Kind: EdgeExposes, Port: port, Public: public, Label: label})
}

func (g *Graph) Node(id string) *Node { return g.index[id] }

func (g *Graph) NodesOf(k Kind) []*Node {
	var out []*Node
	for _, n := range g.Nodes {
		if n.Kind == k {
			out = append(out, n)
		}
	}
	return out
}

func (g *Graph) EdgesTo(id string, k EdgeKind) []*Edge {
	var out []*Edge
	for _, e := range g.Edges {
		if e.To == id && e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func (g *Graph) Merge(o *Graph) {
	for _, n := range o.Nodes {
		g.AddNode(n)
	}
	for _, e := range o.Edges {
		g.AddEdge(e)
	}
	g.Warnings = append(g.Warnings, o.Warnings...)
}

func (g *Graph) RemoveNode(id string) {
	delete(g.index, id)
	nodes := g.Nodes[:0]
	for _, n := range g.Nodes {
		if n.ID != id {
			nodes = append(nodes, n)
		}
	}
	g.Nodes = nodes
	edges := g.Edges[:0]
	for _, e := range g.Edges {
		if e.From == id || e.To == id {
			delete(g.edges, *e)
		} else {
			edges = append(edges, e)
		}
	}
	g.Edges = edges
}

// Sort makes output stable so reports diff cleanly between runs.
func (g *Graph) Sort() {
	sort.SliceStable(g.Nodes, func(i, j int) bool {
		a, b := g.Nodes[i], g.Nodes[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	sort.SliceStable(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
}

// Namespaced copies g with every ID scoped to server, so graphs from several
// servers can be merged. The internet node stays shared.
func (g *Graph) Namespaced(server string) *Graph {
	id := func(s string) string {
		if s == "internet" {
			return s
		}
		return server + "::" + s
	}
	out := New()
	for _, n := range g.Nodes {
		c := *n
		c.ID, c.Server = id(n.ID), server
		if n.ID == "host" {
			c.Name = server + " (localhost only)"
		}
		out.AddNode(&c)
	}
	for _, e := range g.Edges {
		c := *e
		c.From, c.To = id(e.From), id(e.To)
		out.AddEdge(&c)
	}
	for _, w := range g.Warnings {
		out.Warnings = append(out.Warnings, server+": "+w)
	}
	out.Servers = []HostInfo{g.Host}
	return out
}

// LinkConnections turns observed outbound connections ("connects") into
// talks-to edges by matching each peer address to the node listening there:
// a container by its own IP and port, or anything published on a server address.
func (g *Graph) LinkConnections() {
	servers := g.Servers
	if len(servers) == 0 {
		servers = []HostInfo{g.Host}
	}
	addrsOf := map[string][]string{}
	for _, h := range servers {
		addrsOf[h.Hostname] = h.Addrs
	}
	at := map[string]string{}
	for _, e := range g.Edges {
		n := g.Node(e.To)
		if e.Kind != EdgeExposes || n == nil || e.Port == 0 {
			continue
		}
		server := n.Server
		if server == "" {
			server = g.Host.Hostname
		}
		for _, a := range addrsOf[server] {
			if k := net.JoinHostPort(a, strconv.Itoa(e.Port)); at[k] == "" {
				at[k] = n.ID
			}
		}
	}
	// Container IPs are private to their server's Docker networks, so scope them.
	for _, n := range g.Nodes {
		for _, ip := range n.Lists["ips"] {
			for _, p := range n.Lists["ports"] {
				at[n.Server+"|"+net.JoinHostPort(ip, p)] = n.ID
			}
		}
	}
	for _, n := range g.Nodes {
		for _, peer := range n.Lists["connects"] {
			to := at[n.Server+"|"+peer]
			if to == "" {
				to = at[peer]
			}
			if to != "" && to != n.ID {
				g.observe(n.ID, to)
			}
		}
	}
}

// observe records a seen connection, replacing any link that was only inferred.
func (g *Graph) observe(from, to string) {
	for _, e := range g.Edges {
		if e.Kind == EdgeTalksTo && e.From == from && e.To == to && e.Label != "observed" {
			delete(g.edges, *e)
			e.Label = "observed"
			g.edges[*e] = true
		}
	}
	g.AddEdge(&Edge{From: from, To: to, Kind: EdgeTalksTo, Label: "observed"})
}
