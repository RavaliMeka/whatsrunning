package rules

import (
	"testing"

	"github.com/RavaliMeka/whatsrunning/internal/demo"
	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

func has(fs []Finding, rule, node string) bool {
	for _, f := range fs {
		if f.Rule == rule && f.NodeID == node {
			return true
		}
	}
	return false
}

func TestDemoFindings(t *testing.T) {
	g := demo.Graph()
	fs := Evaluate(g)
	want := [][2]string{
		{"exposed-datastore", "prod-web-01::ctr:shop-db-1"},
		{"exposed-datastore", "prod-web-01::proc:mysqld"},
		{"exposed-admin-ui", "prod-web-01::ctr:portainer"},
		{"docker-socket-mounted", "prod-web-01::ctr:portainer"},
		{"datastore-no-volume", "prod-web-01::ctr:shop-redis-1"},
		{"no-restart-policy", "prod-web-01::ctr:shop-worker-1"},
		{"stopped-container", "prod-web-01::ctr:test-api-old"},
		{"unused-volume", "prod-web-01::vol:old_backup_2023"},
		{"latest-tag", "prod-web-01::ctr:monitoring-grafana-1"},
		{"plain-http-site", "prod-web-01::domain:grafana.example.com"},
		{"proxy-bypass", "prod-web-01::domain:grafana.example.com"},
		{"dead-route", "prod-web-01::domain:shop.example.com"},
		{"exposed-datastore", "prod-db-01::proc:postgres"},
	}
	for _, w := range want {
		if !has(fs, w[0], w[1]) {
			t.Errorf("missing %s on %s", w[0], w[1])
		}
	}
	// Things that must NOT be flagged.
	notWant := [][2]string{
		{"exposed-datastore", "prod-web-01::ctr:monitoring-prometheus-1"}, // localhost only
		{"exposed-datastore", "prod-web-01::proc:sshd"},
		{"datastore-no-volume", "prod-web-01::ctr:shop-db-1"}, // has a named volume
		{"runs-as-root", "prod-web-01::ctr:shop-db-1"},        // postgres drops privileges itself
		{"plain-http-site", "prod-web-01::domain:shop.example.com"},
		{"plain-http-site", "prod-web-01::domain:www.shop.example.com"}, // redirect only
		{"proxy-bypass", "prod-web-01::domain:shop.example.com"},        // web is on localhost only
	}
	for _, w := range notWant {
		if has(fs, w[0], w[1]) {
			t.Errorf("false positive %s on %s", w[0], w[1])
		}
	}
	linked := false
	for _, e := range g.Edges {
		linked = linked || (e.From == "prod-web-01::ctr:shop-worker-1" && e.To == "prod-db-01::proc:postgres" && e.Label == "observed")
	}
	if !linked {
		t.Error("demo should show the observed web-01 -> db-01 connection")
	}
	for i := 1; i < len(fs); i++ {
		if Rank(fs[i].Severity) < Rank(fs[i-1].Severity) {
			t.Fatal("findings not sorted by severity")
		}
	}
}

func TestLocalhostDatabaseIsFine(t *testing.T) {
	g := graph.New()
	n := g.AddNode(&graph.Node{ID: "ctr:db", Kind: graph.KindContainer, Name: "db",
		Attrs: map[string]string{"image": "postgres:16", "running": "true", "restart": "always", "user": "root (default)"},
		Lists: map[string][]string{"mounts": {"pgdata -> /var/lib/postgresql/data (rw)"}}})
	g.Expose(n.ID, 5432, false, "127.0.0.1:5432")
	if fs := Evaluate(g); len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestImageTag(t *testing.T) {
	for in, want := range map[string]string{
		"nginx": "latest", "nginx:1.27": "1.27", "registry:5000/app": "latest",
		"registry:5000/app:v2": "v2", "redis@sha256:abc": "digest",
	} {
		if got := imageTag(in); got != want {
			t.Errorf("imageTag(%q)=%q want %q", in, got, want)
		}
	}
}

func TestDomainRules(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "ctr:proxy", Kind: graph.KindContainer, Name: "proxy", Attrs: map[string]string{"image": "nginx:1.27", "running": "true", "restart": "always"}})
	g.Expose("ctr:proxy", 443, true, "0.0.0.0:443")
	g.AddNode(&graph.Node{ID: "ctr:web", Kind: graph.KindContainer, Name: "web", Attrs: map[string]string{"image": "app:1", "running": "true", "restart": "always", "user": "app"}})
	g.Expose("ctr:web", 8081, true, "0.0.0.0:8081")
	g.AddNode(&graph.Node{ID: "ctr:api", Kind: graph.KindContainer, Name: "api", Attrs: map[string]string{"image": "api:1", "running": "true", "restart": "always", "user": "app"}})

	add := func(name, tls, plain string, unresolved ...string) {
		g.AddNode(&graph.Node{ID: "domain:" + name, Kind: graph.KindDomain, Name: name,
			Attrs: map[string]string{"tls": tls, "plain_http_serves": plain, "served_by": "proxy"},
			Lists: map[string][]string{"unresolved": unresolved}})
	}
	add("open.test", "false", "true", "/old/ -> http://10.0.0.9:9000")
	add("mixed.test", "true", "true")
	add("good.test", "true", "false")
	g.AddEdge(&graph.Edge{From: "domain:open.test", To: "ctr:web", Kind: graph.EdgeRoutes, Label: "/"})
	g.AddEdge(&graph.Edge{From: "domain:good.test", To: "ctr:api", Kind: graph.EdgeRoutes, Label: "/"})
	g.AddEdge(&graph.Edge{From: "domain:good.test", To: "ctr:proxy", Kind: graph.EdgeRoutes, Label: "/static"})

	fs := Evaluate(g)
	for _, w := range [][2]string{
		{"plain-http-site", "domain:open.test"}, {"proxy-bypass", "domain:open.test"}, {"dead-route", "domain:open.test"},
		{"http-without-redirect", "domain:mixed.test"},
	} {
		if !has(fs, w[0], w[1]) {
			t.Errorf("missing %s on %s", w[0], w[1])
		}
	}
	for _, rule := range []string{"plain-http-site", "http-without-redirect", "proxy-bypass", "dead-route"} {
		if has(fs, rule, "domain:good.test") {
			t.Errorf("false positive %s on good.test (TLS, internal target, route to nginx itself)", rule)
		}
	}
	if has(fs, "plain-http-site", "domain:mixed.test") {
		t.Error("a TLS site is not plain HTTP")
	}
}
