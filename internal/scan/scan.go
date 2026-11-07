// Package scan runs the available collectors and merges their output.
package scan

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/RavaliMeka/whatsrunning/internal/collector"
	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

func Run(ctx context.Context, cs []collector.Collector) *graph.Graph {
	g := graph.New()
	for _, c := range cs {
		if !c.Available() {
			g.Warnings = append(g.Warnings, c.Name()+": not available here, skipped")
			continue
		}
		part, err := c.Collect(ctx)
		if err != nil {
			g.Warnings = append(g.Warnings, c.Name()+": "+err.Error())
			continue
		}
		if part.Host.Docker != "" {
			g.Host.Docker = part.Host.Docker
		}
		g.Merge(part)
	}
	foldHostNetwork(g)
	g.Host.Hostname, _ = os.Hostname()
	g.Host.OS = osName()
	g.Host.ScannedAt = time.Now().UTC()
	g.Sort()
	return g
}

// foldHostNetwork moves listeners owned by host-network containers from the
// process node onto the container, so they are not drawn twice.
func foldHostNetwork(g *graph.Graph) {
	byID := map[string]*graph.Node{}
	for _, n := range g.NodesOf(graph.KindContainer) {
		byID[n.Attrs["id"]] = n
	}
	for _, p := range g.NodesOf(graph.KindProcess) {
		cid := p.Attrs["container_id"]
		c := byID[cid[:min(12, len(cid))]]
		if cid == "" || c == nil {
			continue
		}
		for _, e := range g.EdgesTo(p.ID, graph.EdgeExposes) {
			g.Expose(c.ID, e.Port, e.Public, e.Label)
			c.Lists["published"] = append(c.Lists["published"], e.Label+" (host network)")
		}
		g.RemoveNode(p.ID)
	}
}

func osName() string {
	b, _ := os.ReadFile("/etc/os-release")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "linux"
}
