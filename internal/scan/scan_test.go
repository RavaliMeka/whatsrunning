package scan

import (
	"testing"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

func talks(g *graph.Graph) map[string]string {
	out := map[string]string{}
	for _, e := range g.Edges {
		if e.Kind == graph.EdgeTalksTo {
			out[e.From] = e.To
		}
	}
	return out
}

func TestCombineLinksServersByObservedConnections(t *testing.T) {
	web := graph.New()
	web.Host = graph.HostInfo{Hostname: "web-01", Addrs: []string{"10.0.0.4"}}
	web.AddNode(&graph.Node{ID: "ctr:api", Kind: graph.KindContainer, Name: "api",
		Lists: map[string][]string{"ips": {"172.17.0.2"}, "ports": {"3000"}, "connects": {"10.0.0.5:5432", "172.17.0.3:6379"}}})

	db := graph.New()
	db.Host = graph.HostInfo{Hostname: "db-01", Addrs: []string{"10.0.0.5"}}
	db.AddNode(&graph.Node{ID: "proc:postgres", Kind: graph.KindProcess, Name: "postgres"})
	db.Expose("proc:postgres", 5432, true, "0.0.0.0:5432")
	// Same private Docker IP as a container could have on web-01: must not be linked across servers.
	db.AddNode(&graph.Node{ID: "ctr:cache", Kind: graph.KindContainer, Name: "cache",
		Lists: map[string][]string{"ips": {"172.17.0.3"}, "ports": {"6379"}}})

	g := Combine([]Part{{Target: "web", Graph: web}, {Target: "db", Graph: db}})

	if len(g.Servers) != 2 || g.Node("web-01::ctr:api") == nil || g.Node("db-01::proc:postgres").Server != "db-01" {
		t.Fatalf("servers not namespaced: %+v", g.Servers)
	}
	got := talks(g)
	if got["web-01::ctr:api"] != "db-01::proc:postgres" {
		t.Errorf("cross-server link missing: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("private Docker IP linked across servers: %v", got)
	}
	if g.Node("internet") == nil {
		t.Error("internet node should be shared")
	}
}

func TestCombineNamesDuplicateHostnamesByTarget(t *testing.T) {
	a, b := graph.New(), graph.New()
	a.Host.Hostname, b.Host.Hostname = "ubuntu", "ubuntu"
	g := Combine([]Part{{Target: "a.example", Graph: a}, {Target: "b.example", Graph: b}})
	if g.Servers[0].Hostname != "ubuntu" || g.Servers[1].Hostname != "b.example" {
		t.Fatalf("servers = %+v", g.Servers)
	}
}
