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
	fs := Evaluate(demo.Graph())
	want := [][2]string{
		{"exposed-datastore", "ctr:shop-db-1"},
		{"exposed-datastore", "proc:mysqld"},
		{"exposed-admin-ui", "ctr:portainer"},
		{"docker-socket-mounted", "ctr:portainer"},
		{"datastore-no-volume", "ctr:shop-redis-1"},
		{"no-restart-policy", "ctr:shop-worker-1"},
		{"stopped-container", "ctr:test-api-old"},
		{"unused-volume", "vol:old_backup_2023"},
		{"latest-tag", "ctr:monitoring-grafana-1"},
	}
	for _, w := range want {
		if !has(fs, w[0], w[1]) {
			t.Errorf("missing %s on %s", w[0], w[1])
		}
	}
	// Things that must NOT be flagged.
	notWant := [][2]string{
		{"exposed-datastore", "ctr:monitoring-prometheus-1"}, // localhost only
		{"exposed-datastore", "proc:sshd"},
		{"datastore-no-volume", "ctr:shop-db-1"}, // has a named volume
		{"runs-as-root", "ctr:shop-db-1"},        // postgres drops privileges itself
	}
	for _, w := range notWant {
		if has(fs, w[0], w[1]) {
			t.Errorf("false positive %s on %s", w[0], w[1])
		}
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
