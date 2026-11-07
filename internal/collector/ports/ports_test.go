package ports

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:0035", "127.0.0.1", 53},
		{"00000000:1538", "0.0.0.0", 5432},
		{"00000000000000000000000000000000:0016", "::", 22},
		{"00000000000000000000000001000000:1F90", "::1", 8080},
	}
	for _, c := range cases {
		ip, port, err := parseAddr(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if ip.String() != c.ip || port != c.port {
			t.Errorf("%s: got %s:%d want %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestSocketsAndOutbound(t *testing.T) {
	dir := t.TempDir()
	// listen :5432; inbound 10.0.0.9 -> :5432 (ignored); outbound -> 10.0.0.5:6379; outbound to loopback (ignored)
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 111 1 0 100 0 0 10 0
   1: 0200000A:1538 0900000A:D431 01 00000000:00000000 00:00000000 00000000   999        0 112 1 0 100 0 0 10 0
   2: 0200000A:A1B2 0500000A:18EB 01 00000000:00000000 00:00000000 00000000   999        0 113 1 0 100 0 0 10 0
   3: 0100007F:A1B3 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 114 1 0 20 4 30 10 -1
`
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	socks, err := readSockets(dir)
	if err != nil || len(socks) != 4 || !socks[0].listen || socks[0].port != 5432 {
		t.Fatalf("readSockets: %+v, %v", socks, err)
	}
	if got := Outbound(dir); len(got) != 1 || got[0] != "10.0.0.5:6379" {
		t.Fatalf("Outbound = %v, want [10.0.0.5:6379]", got)
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"app --db-password=hunter2 --port 80 --api-token abc123": "app --db-password=*** --port 80 --api-token ***",
		"worker postgres://app:s3cr3t@db:5432/app":               "worker postgres://app:***@db:5432/app",
	} {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}
