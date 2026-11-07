// Package demo builds two sample servers with typical problems, for
// `whatsrunning demo` and the hosted live demo.
package demo

import (
	"strconv"
	"strings"
	"time"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
	"github.com/RavaliMeka/whatsrunning/internal/scan"
)

type ctr struct {
	name, project, image, user, restart string
	stopped                             bool
	ports                               []string // "bind:host:container"
	mounts                              []string // "source:destination"
	env                                 []string
	calls                               []string
}

var containers = []ctr{
	{name: "shop-nginx-1", project: "shop", image: "nginx:1.27-alpine", ports: []string{"0.0.0.0:80:80", "0.0.0.0:443:443"},
		mounts: []string{"/etc/letsencrypt:/etc/letsencrypt", "/srv/shop/nginx.conf:/etc/nginx/nginx.conf"}, calls: []string{"shop-web-1"}},
	{name: "shop-web-1", project: "shop", image: "registry.example.com/shop/web:latest", user: "node", ports: []string{"127.0.0.1:3000:3000"},
		env: []string{"NODE_ENV", "DATABASE_URL", "REDIS_URL", "STRIPE_SECRET_KEY"}, calls: []string{"shop-db-1", "shop-redis-1"}},
	{name: "shop-worker-1", project: "shop", image: "registry.example.com/shop/web:latest", user: "node", restart: "no",
		env: []string{"DATABASE_URL", "REDIS_URL", "QUEUE"}, calls: []string{"shop-db-1", "shop-redis-1"}},
	{name: "shop-db-1", project: "shop", image: "postgres:16", ports: []string{"0.0.0.0:5432:5432"},
		mounts: []string{"shop_pgdata:/var/lib/postgresql/data"}, env: []string{"POSTGRES_PASSWORD", "POSTGRES_DB"}},
	{name: "shop-redis-1", project: "shop", image: "redis:7"},
	{name: "monitoring-grafana-1", project: "monitoring", image: "grafana/grafana:latest", user: "472", ports: []string{"0.0.0.0:3001:3000"},
		mounts: []string{"monitoring_grafana:/var/lib/grafana"}, calls: []string{"monitoring-prometheus-1"}},
	{name: "monitoring-prometheus-1", project: "monitoring", image: "prom/prometheus:v2.53.0", user: "nobody", ports: []string{"127.0.0.1:9090:9090"},
		mounts: []string{"monitoring_prom:/prometheus", "/srv/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml"}},
	{name: "portainer", image: "portainer/portainer-ce", ports: []string{"0.0.0.0:9000:9000"},
		mounts: []string{"/var/run/docker.sock:/var/run/docker.sock", "portainer_data:/data"}},
	{name: "test-api-old", image: "shop-api:dev", restart: "no", stopped: true, ports: []string{"0.0.0.0:8080:8080"}},
	{name: "mongo-tmp", image: "mongo:4.4", restart: "no", stopped: true, mounts: []string{"9f3c2a7d1b4e8f6a0c5d2e9b7a1f3c8d4e6b2a9f7c1d3e5b8a0f2c4d6e8a1b3c:/data/db"}},
}

func Graph() *graph.Graph {
	return scan.Combine([]scan.Part{{Target: "prod-web-01", Graph: web()}, {Target: "prod-db-01", Graph: db()}})
}

func web() *graph.Graph {
	g := graph.New()
	g.Host = graph.HostInfo{Hostname: "prod-web-01", OS: "Ubuntu 22.04.4 LTS", Docker: "27.3.1", Addrs: []string{"10.0.1.10"}, ScannedAt: time.Now().UTC()}

	for _, c := range containers {
		user, restart, status, exit := c.user, c.restart, "running", "0"
		if user == "" {
			user = "root (default)"
		}
		if restart == "" {
			restart = "unless-stopped"
		}
		if c.stopped {
			status, exit = "exited", "137"
		}
		n := g.AddNode(&graph.Node{ID: "ctr:" + c.name, Kind: graph.KindContainer, Name: c.name, Group: c.project, Status: status,
			Attrs: map[string]string{"image": c.image, "user": user, "restart": restart, "running": strconv.FormatBool(!c.stopped),
				"exit_code": exit, "privileged": "false", "network_mode": "bridge"},
			Lists: map[string][]string{"env": c.env}})
		for _, p := range c.ports {
			f := strings.Split(p, ":")
			port, _ := strconv.Atoi(f[1])
			n.Lists["published"] = append(n.Lists["published"], f[0]+":"+f[1]+" -> "+f[2]+"/tcp")
			g.Expose(n.ID, port, f[0] == "0.0.0.0", f[0]+":"+f[1]+"→"+f[2])
		}
		for _, m := range c.mounts {
			src, dst, _ := strings.Cut(m, ":")
			id, name, typ := "vol:"+src, src, "volume"
			if strings.HasPrefix(src, "/") {
				id, typ = "bind:"+src, "bind"
			} else if len(src) == 64 {
				name = "anonymous:" + src[:12]
			}
			g.AddNode(&graph.Node{ID: id, Kind: graph.KindVolume, Name: name, Status: "in use", Attrs: map[string]string{"type": typ, "full_name": src}})
			g.AddEdge(&graph.Edge{From: n.ID, To: id, Kind: graph.EdgeMounts, Label: dst + " (rw)"})
			n.Lists["mounts"] = append(n.Lists["mounts"], name+" -> "+dst+" (rw)")
		}
		for _, to := range c.calls {
			g.AddEdge(&graph.Edge{From: n.ID, To: "ctr:" + to, Kind: graph.EdgeTalksTo, Label: "env reference"})
		}
	}

	for _, p := range []struct{ name, cmd, addr string }{
		{"sshd", "sshd: /usr/sbin/sshd -D", "0.0.0.0:22"},
		{"mysqld", "/usr/sbin/mysqld", "0.0.0.0:3306"},
		{"systemd-resolve", "/lib/systemd/systemd-resolved", "127.0.0.53:53"},
	} {
		id := "proc:" + p.name
		bind, port, _ := strings.Cut(p.addr, ":")
		n := g.AddNode(&graph.Node{ID: id, Kind: graph.KindProcess, Name: p.name, Status: "listening", Attrs: map[string]string{"cmdline": p.cmd}})
		n.Lists["listening"], n.Lists["ports"] = []string{p.addr}, []string{port}
		portNum, _ := strconv.Atoi(port)
		g.Expose(id, portNum, bind == "0.0.0.0", p.addr)
	}

	for _, v := range []string{"old_backup_2023", "a71c09e5d3b2f84c6e1a9d0b7f5c3e2a8d4b6f1c9e7a3d5b0f2e4c6a8b1d3f5e"} {
		name := v
		if len(v) == 64 {
			name = "anonymous:" + v[:12]
		}
		g.AddNode(&graph.Node{ID: "vol:" + v, Kind: graph.KindVolume, Name: name, Status: "unused", Attrs: map[string]string{"driver": "local", "full_name": v}})
	}
	g.Node("ctr:shop-worker-1").Lists["connects"] = []string{"10.0.1.20:5432"}

	domain := func(name string, tls, plain bool, routes map[string]string, unresolved ...string) {
		id := "domain:" + name
		g.AddNode(&graph.Node{ID: id, Kind: graph.KindDomain, Name: name, Status: "nginx",
			Attrs: map[string]string{"served_by": "shop-nginx-1", "tls": strconv.FormatBool(tls), "plain_http_serves": strconv.FormatBool(plain)},
			Lists: map[string][]string{"listen": {"80", "443"}, "unresolved": unresolved}})
		g.Expose(id, 443, true, ":443")
		for path, to := range routes {
			g.Node(id).Lists["routes"] = append(g.Node(id).Lists["routes"], path+" -> "+to)
			g.AddEdge(&graph.Edge{From: id, To: "ctr:" + to, Kind: graph.EdgeRoutes, Label: path})
		}
	}
	domain("shop.example.com", true, false, map[string]string{"/": "shop-web-1"}, "/admin/ -> http://127.0.0.1:9999")
	domain("www.shop.example.com", false, false, nil)
	domain("grafana.example.com", false, true, map[string]string{"/": "monitoring-grafana-1"})
	return g
}

func db() *graph.Graph {
	g := graph.New()
	g.Host = graph.HostInfo{Hostname: "prod-db-01", OS: "Debian 12", Addrs: []string{"10.0.1.20"}, ScannedAt: time.Now().UTC()}
	for _, p := range []struct{ name, cmd, addr string }{
		{"postgres", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", "0.0.0.0:5432"},
		{"sshd", "sshd: /usr/sbin/sshd -D", "0.0.0.0:22"},
		{"node_exporter", "/usr/local/bin/node_exporter", "0.0.0.0:9100"},
	} {
		id := "proc:" + p.name
		bind, port, _ := strings.Cut(p.addr, ":")
		n := g.AddNode(&graph.Node{ID: id, Kind: graph.KindProcess, Name: p.name, Status: "listening", Attrs: map[string]string{"cmdline": p.cmd}})
		n.Lists["listening"], n.Lists["ports"] = []string{p.addr}, []string{port}
		portNum, _ := strconv.Atoi(port)
		g.Expose(id, portNum, bind == "0.0.0.0", p.addr)
	}
	return g
}
