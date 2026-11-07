package nginx

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

func write(t *testing.T, root, path, body string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func routes(g *graph.Graph, from string) []string {
	var out []string
	for _, e := range g.Edges {
		if e.From == from && e.Kind == graph.EdgeRoutes {
			out = append(out, e.Label+" "+e.To)
		}
	}
	return out
}

func TestTokenize(t *testing.T) {
	got := tokenize("server_name a.com 'b c'; # note\nlocation / { proxy_pass \"http://x\"; }")
	want := []string{"server_name", "a.com", "b c", ";", "location", "/", "{", "proxy_pass", "http://x", ";", "}"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestHostNginx(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/nginx/nginx.conf", `
events {}
http {
  upstream app { server 127.0.0.1:3000 weight=2; }
  include sites-enabled/*;
}`)
	write(t, root, "etc/nginx/sites-enabled/shop", `
server { listen 80; server_name shop.example.com www.shop.example.com; return 301 https://$host$request_uri; }
server {
  listen 443 ssl;
  server_name shop.example.com;
  location / { proxy_pass http://app; }
  location /api/ { proxy_pass http://127.0.0.1:9999; }  # nothing listens here
}`)
	write(t, root, "etc/nginx/sites-enabled/grafana", `
server { listen 80; server_name grafana.example.com; location / { proxy_pass "http://localhost:3001"; } }`)

	g := graph.New()
	nginx := g.AddNode(&graph.Node{ID: "proc:nginx", Kind: graph.KindProcess, Name: "nginx"})
	g.Expose(nginx.ID, 80, true, "0.0.0.0:80")
	g.Expose(nginx.ID, 443, true, "0.0.0.0:443")
	g.AddNode(&graph.Node{ID: "proc:node", Kind: graph.KindProcess, Name: "node"})
	g.Expose("proc:node", 3000, false, "127.0.0.1:3000")
	g.AddNode(&graph.Node{ID: "ctr:grafana", Kind: graph.KindContainer, Name: "grafana", Attrs: map[string]string{"image": "grafana/grafana"}})
	g.Expose("ctr:grafana", 3001, true, "0.0.0.0:3001→3000")

	Enrich(g, root)

	shop := g.Node("domain:shop.example.com")
	if shop == nil || shop.Attrs["tls"] != "true" || shop.Attrs["plain_http_serves"] != "false" {
		t.Fatalf("shop: %+v", shop)
	}
	if r := routes(g, shop.ID); !slices.Equal(r, []string{"/ proc:node"}) {
		t.Errorf("shop routes = %v", r)
	}
	if u := shop.Lists["unresolved"]; !slices.Equal(u, []string{"/api/ -> http://127.0.0.1:9999"}) {
		t.Errorf("shop unresolved = %v", u)
	}
	if www := g.Node("domain:www.shop.example.com"); www == nil || www.Attrs["plain_http_serves"] != "false" {
		t.Errorf("www redirect-only site: %+v", www)
	}
	gr := g.Node("domain:grafana.example.com")
	if gr == nil || gr.Attrs["tls"] != "false" || gr.Attrs["plain_http_serves"] != "true" {
		t.Fatalf("grafana: %+v", gr)
	}
	if r := routes(g, gr.ID); !slices.Equal(r, []string{"/ ctr:grafana"}) {
		t.Errorf("grafana routes = %v", r)
	}
	if len(g.EdgesTo(gr.ID, graph.EdgeExposes)) == 0 {
		t.Error("public domain is not linked from the internet")
	}
}

func TestContainerNginxThroughBindMount(t *testing.T) {
	root := t.TempDir()
	write(t, root, "srv/proxy/conf.d/app.conf", `server { listen 80; server_name app.test; location / { proxy_pass http://web:8000; } }`)

	g := graph.New()
	ng := g.AddNode(&graph.Node{ID: "ctr:proxy", Kind: graph.KindContainer, Name: "proxy",
		Attrs: map[string]string{"image": "nginx:1.27-alpine", "running": "true"},
		Lists: map[string][]string{"published": {"0.0.0.0:8080 -> 80/tcp"}}})
	g.Expose(ng.ID, 8080, true, "0.0.0.0:8080→80")
	g.AddNode(&graph.Node{ID: "bind:/srv/proxy/conf.d", Kind: graph.KindVolume})
	g.AddEdge(&graph.Edge{From: ng.ID, To: "bind:/srv/proxy/conf.d", Kind: graph.EdgeMounts, Label: "/etc/nginx/conf.d (ro)"})
	g.AddNode(&graph.Node{ID: "ctr:web", Kind: graph.KindContainer, Name: "web",
		Lists: map[string][]string{"hostnames": {"web", "shop-web-1"}, "ports": {"8000"}}})

	Enrich(g, root)

	d := g.Node("domain:app.test")
	if d == nil {
		t.Fatalf("domain not found; warnings: %v", g.Warnings)
	}
	if r := routes(g, d.ID); !slices.Equal(r, []string{"/ ctr:web"}) {
		t.Errorf("routes = %v", r)
	}
	if e := g.EdgesTo(d.ID, graph.EdgeExposes); len(e) != 1 || e[0].Port != 8080 {
		t.Errorf("domain should be reachable on published port 8080, got %+v", e)
	}
}

func TestIncludeLoopIsBounded(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/nginx/nginx.conf", "include nginx.conf;")
	g := graph.New()
	g.AddNode(&graph.Node{ID: "proc:nginx", Kind: graph.KindProcess, Name: "nginx"})
	Enrich(g, root) // must return
}
