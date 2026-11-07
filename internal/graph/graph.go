// Package graph is the model every collector writes into and every renderer reads.
package graph

import (
	"sort"
	"time"
)

type Kind string

const (
	KindEntry     Kind = "internet" // internet or localhost
	KindContainer Kind = "container"
	KindProcess   Kind = "process"
	KindVolume    Kind = "volume"
)

type EdgeKind string

const (
	EdgeExposes EdgeKind = "exposes"
	EdgeMounts  EdgeKind = "mounts"
	EdgeTalksTo EdgeKind = "talks-to"
)

type Node struct {
	ID     string              `json:"id"`
	Kind   Kind                `json:"kind"`
	Name   string              `json:"name"`
	Group  string              `json:"group,omitempty"`
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
	ScannedAt time.Time `json:"scannedAt"`
}

type Graph struct {
	Host     HostInfo `json:"host"`
	Nodes    []*Node  `json:"nodes"`
	Edges    []*Edge  `json:"edges"`
	Warnings []string `json:"warnings,omitempty"`
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
