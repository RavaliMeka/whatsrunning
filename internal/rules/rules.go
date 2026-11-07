// Package rules turns a graph into findings with a plain-English reason and fix.
package rules

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

var rank = map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3}

// Rank orders severities, most severe first. Unknown values rank last.
func Rank(s Severity) int {
	if r, ok := rank[s]; ok {
		return r
	}
	return len(rank)
}

type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	NodeID   string   `json:"nodeId"`
	Title    string   `json:"title"`
	Why      string   `json:"why"`
	Fix      string   `json:"fix"`
}

type store struct{ match, label, dataDir string }

var stores = []store{
	{"postgres", "PostgreSQL", "/var/lib/postgresql/data"}, {"postgis", "PostgreSQL", "/var/lib/postgresql/data"},
	{"timescale", "PostgreSQL", "/var/lib/postgresql/data"}, {"mysql", "MySQL", "/var/lib/mysql"},
	{"mariadb", "MariaDB", "/var/lib/mysql"}, {"mongo", "MongoDB", "/data/db"}, {"redis", "Redis", "/data"},
	{"valkey", "Valkey", "/data"}, {"keydb", "KeyDB", "/data"}, {"elasticsearch", "Elasticsearch", "/usr/share/elasticsearch/data"},
	{"opensearch", "OpenSearch", "/usr/share/opensearch/data"}, {"cassandra", "Cassandra", "/var/lib/cassandra"},
	{"couchdb", "CouchDB", "/opt/couchdb/data"}, {"influxdb", "InfluxDB", "/var/lib/influxdb2"},
	{"clickhouse", "ClickHouse", "/var/lib/clickhouse"}, {"memcached", "Memcached", ""}, {"mssql", "SQL Server", "/var/opt/mssql"},
	{"rabbitmq", "RabbitMQ", "/var/lib/rabbitmq"}, {"etcd", "etcd", "/etcd-data"},
}

// Native process names (from /proc/<pid>/comm, max 15 chars) of datastores.
var procStores = map[string]string{
	"postgres": "PostgreSQL", "mysqld": "MySQL", "mariadbd": "MariaDB", "mongod": "MongoDB", "redis-server": "Redis",
	"memcached": "Memcached", "influxd": "InfluxDB", "clickhouse-serv": "ClickHouse", "etcd": "etcd",
}

var adminUIs = []struct{ match, label string }{
	{"portainer", "Portainer"}, {"adminer", "Adminer"}, {"phpmyadmin", "phpMyAdmin"}, {"pgadmin", "pgAdmin"},
	{"mongo-express", "mongo-express"}, {"redis-commander", "Redis Commander"}, {"kibana", "Kibana"},
	{"grafana", "Grafana"}, {"prometheus", "Prometheus"}, {"traefik", "Traefik dashboard"}, {"jenkins", "Jenkins"},
}

// Official images whose entrypoint drops to an unprivileged user by itself.
var dropsRoot = []string{"postgres", "redis", "mysql", "mariadb", "mongo", "nginx", "rabbitmq", "elasticsearch", "httpd", "valkey", "memcached"}

func imageBase(img string) string {
	img = strings.ToLower(img)
	return img[strings.LastIndex(img, "/")+1:]
}

func storeOf(n *graph.Node) (store, bool) {
	if n.Kind == graph.KindProcess {
		l, ok := procStores[n.Name]
		return store{label: l}, ok
	}
	base := imageBase(n.Attrs["image"])
	for _, s := range stores {
		if strings.Contains(base, s.match) {
			return s, true
		}
	}
	return store{}, false
}

func imageTag(img string) string {
	if strings.Contains(img, "@sha256:") {
		return "digest"
	}
	last := img[strings.LastIndex(img, "/")+1:]
	if i := strings.LastIndex(last, ":"); i >= 0 {
		return last[i+1:]
	}
	return "latest"
}

func publicPorts(g *graph.Graph, id string) []string {
	var out []string
	for _, e := range g.EdgesTo(id, graph.EdgeExposes) {
		if p := strconv.Itoa(e.Port); e.Public && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

type addFunc func(rule string, sev Severity, title, why, fix string)

func Evaluate(g *graph.Graph) []Finding {
	fs := []Finding{}
	for _, n := range g.Nodes {
		add := func(rule string, sev Severity, title, why, fix string) {
			if n.Server != "" {
				title = n.Server + ": " + title
			}
			fs = append(fs, Finding{rule, sev, n.ID, title, why, fix})
		}
		switch n.Kind {
		case graph.KindVolume:
			if n.Status == "unused" {
				add("unused-volume", Low, "Volume "+n.Name+" is not used by any container",
					"Leftover volumes take disk space and can hold old, sensitive data nobody remembers.",
					"Check its contents, then: docker volume rm "+n.Attrs["full_name"])
			}
		case graph.KindProcess:
			checkExposedStore(g, n, add)
			if pub := publicPorts(g, n.ID); n.Name == "dockerd" && len(pub) > 0 {
				add("docker-api-exposed", Critical, "The Docker API is listening on the network (port "+strings.Join(pub, ", ")+")",
					"Anyone who can reach this port can start a privileged container and take over the server.",
					"Remove the tcp:// -H flag from dockerd, or require TLS client certificates.")
			}
		case graph.KindContainer:
			checkExposedStore(g, n, add)
			checkContainer(g, n, add)
		case graph.KindDomain:
			checkDomain(g, n, add)
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if Rank(fs[i].Severity) != Rank(fs[j].Severity) {
			return Rank(fs[i].Severity) < Rank(fs[j].Severity)
		}
		return fs[i].NodeID < fs[j].NodeID
	})
	return fs
}

func checkExposedStore(g *graph.Graph, n *graph.Node, add addFunc) {
	s, ok := storeOf(n)
	pub := publicPorts(g, n.ID)
	if !ok || len(pub) == 0 {
		return
	}
	why := "It accepts connections on every network interface. Exposed databases are found by scanners within minutes and are a leading cause of data leaks and ransom attacks."
	fix := "Remove the port mapping (containers on the same network can still reach it), or bind it to localhost: \"127.0.0.1:" + pub[0] + ":<container port>\"."
	if n.Kind == graph.KindProcess {
		fix = "Listen on 127.0.0.1 only (bind-address / listen_addresses), or block port " + pub[0] + " in the firewall or cloud security group."
	} else {
		why += " Docker-published ports bypass UFW and firewalld, so a host firewall does not protect it."
	}
	add("exposed-datastore", Critical, fmt.Sprintf("%s (%s) is reachable from outside on port %s", s.label, n.Name, strings.Join(pub, ", ")), why, fix)
}

func checkContainer(g *graph.Graph, n *graph.Node, add addFunc) {
	img, base := n.Attrs["image"], imageBase(n.Attrs["image"])
	running := n.Attrs["running"] == "true"
	pub := publicPorts(g, n.ID)
	s, isStore := storeOf(n)
	mounts := n.Lists["mounts"]

	if len(pub) > 0 && !isStore {
		for _, a := range adminUIs {
			if strings.Contains(base, a.match) {
				add("exposed-admin-ui", High, fmt.Sprintf("%s admin UI (%s) is published on port %s", a.label, n.Name, strings.Join(pub, ", ")),
					"Admin panels are a favourite target for brute force and known exploits.",
					"Put it behind a VPN or SSO proxy, or bind it to 127.0.0.1 and use an SSH tunnel.")
				break
			}
		}
	}
	if slices.ContainsFunc(mounts, func(m string) bool { return strings.Contains(m, "docker.sock") }) {
		add("docker-socket-mounted", High, n.Name+" has the Docker socket mounted",
			"Access to docker.sock equals root on the host. If this container is compromised, so is the server.",
			"Mount it only where truly needed, through a read-only socket proxy.")
	}
	if n.Attrs["privileged"] == "true" {
		add("privileged", High, n.Name+" runs in privileged mode",
			"Privileged containers can reach every host device and escape to the host easily.",
			"Remove privileged: true and grant only the capabilities it needs with cap_add.")
	}
	if n.Attrs["network_mode"] == "host" {
		add("host-network", Medium, n.Name+" uses the host network",
			"Every port it opens is opened on the server itself, with no container isolation.",
			"Use a bridge network and publish only the ports you need.")
	}
	if n.Attrs["pid_mode"] == "host" {
		add("host-pid", Medium, n.Name+" shares the host PID namespace",
			"It can see and signal every process on the server.",
			"Remove pid: host unless this is a monitoring agent that needs it.")
	}
	if isStore && running && s.dataDir != "" {
		switch {
		case len(mounts) == 0:
			add("datastore-no-volume", High, s.label+" ("+n.Name+") stores its data inside the container",
				"Recreating or upgrading the container permanently deletes all of its data.",
				"Mount a named volume at "+s.dataDir+" and set up backups.")
		case !slices.ContainsFunc(mounts, func(m string) bool { return !strings.HasPrefix(m, "anonymous:") }):
			add("datastore-anonymous-volume", Medium, s.label+" ("+n.Name+") keeps data in an anonymous volume",
				"Anonymous volumes are easy to delete by accident (docker compose down -v, volume prune) and are not reattached by docker run.",
				"Use a named volume so the data has a clear owner and survives recreation.")
		}
	}
	if running && n.Attrs["restart"] == "no" {
		add("no-restart-policy", Medium, n.Name+" has no restart policy",
			"It stays down after a crash or a reboot.",
			"Set restart: unless-stopped.")
	}
	if !running {
		add("stopped-container", Low, fmt.Sprintf("%s is stopped (exit code %s)", n.Name, n.Attrs["exit_code"]),
			"Stopped containers are often forgotten leftovers that keep old images and data around.",
			"If it is no longer needed: docker rm "+n.Name)
	}
	if imageTag(img) == "latest" {
		add("latest-tag", Low, n.Name+" uses an unpinned image ("+img+")",
			"An unpinned tag can pull a different, possibly breaking, version on the next restart.",
			"Pin a version, e.g. "+strings.TrimSuffix(img, ":latest")+":<version>.")
	}
	if running && len(pub) > 0 && strings.HasPrefix(n.Attrs["user"], "root") &&
		!slices.ContainsFunc(dropsRoot, func(d string) bool { return strings.Contains(base, d) }) {
		add("runs-as-root", Low, n.Name+" runs as root",
			"A vulnerability in a root process gives an attacker more power inside the container and makes escapes easier.",
			"Set a non-root user, e.g. user: \"1000:1000\", if the image supports it.")
	}
}

func checkDomain(g *graph.Graph, n *graph.Node, add addFunc) {
	switch {
	case n.Attrs["tls"] != "true" && n.Attrs["plain_http_serves"] == "true":
		add("plain-http-site", Medium, n.Name+" is served over plain HTTP",
			"Logins, cookies and data sent to this site travel unencrypted and can be read or changed on the way.",
			"Add a TLS certificate (e.g. Let's Encrypt with certbot) and redirect port 80 to https.")
	case n.Attrs["plain_http_serves"] == "true":
		add("http-without-redirect", Low, n.Name+" also answers on plain HTTP without redirecting",
			"Visitors who type the address without https stay on an unencrypted connection.",
			"In the port 80 server block, use: return 301 https://$host$request_uri;")
	}
	for _, e := range g.Edges {
		if e.From != n.ID || e.Kind != graph.EdgeRoutes {
			continue
		}
		target := g.Node(e.To)
		if pub := publicPorts(g, e.To); target != nil && len(pub) > 0 && target.Name != n.Attrs["served_by"] {
			add("proxy-bypass", High, fmt.Sprintf("%s is reachable directly on port %s, bypassing nginx for %s", target.Name, strings.Join(pub, ", "), n.Name),
				"Anything nginx enforces (TLS, authentication, rate limits, IP allow lists) can be skipped by going straight to the port.",
				"Stop publishing the port: nginx reaches the service over the internal network or localhost.")
		}
	}
	for _, u := range n.Lists["unresolved"] {
		add("dead-route", Low, n.Name+" routes "+u+", where nothing is running",
			"Requests to this path fail with 502 Bad Gateway, and a forgotten route can expose whatever starts on that address later.",
			"Remove the location block, or start the service it should reach.")
	}
}

func Counts(fs []Finding) map[Severity]int {
	c := map[Severity]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}
