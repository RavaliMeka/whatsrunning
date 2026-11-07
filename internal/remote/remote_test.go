package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH stands in for the ssh client: it skips the options and destination
// and runs the remote command with sh, logging the destination it was given.
const fakeSSH = `#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift
echo "$1" >> "$LOG"
shift
exec sh -c "$1"
`

// fakeScanner stands in for the uploaded binary.
const fakeScanner = `#!/bin/sh
[ "$1 $2 $3 $4 $5" = "scan -o - -json -" ] || exit 9
echo '{"graph":{"host":{"hostname":"db-01"},"nodes":[{"id":"proc:postgres","kind":"process","name":"postgres"}],"edges":[]},"findings":[]}'
`

func setup(t *testing.T) (Options, string) {
	t.Helper()
	dir := t.TempDir()
	ssh, self := filepath.Join(dir, "ssh"), filepath.Join(dir, "scanner")
	for p, body := range map[string]string{ssh: fakeSSH, self: fakeScanner} {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("LOG", filepath.Join(dir, "log"))
	return Options{SSH: ssh, Self: self}, home
}

func TestScanUploadsRunsAndCleansUp(t *testing.T) {
	o, home := setup(t)
	g, err := Scan(context.Background(), "admin@db-01", o)
	if err != nil {
		t.Fatal(err)
	}
	if g.Host.Hostname != "db-01" || len(g.Nodes) != 1 || g.Nodes[0].ID != "proc:postgres" {
		t.Fatalf("unexpected graph: %+v", g)
	}
	if left, _ := filepath.Glob(filepath.Join(home, ".whatsrunning.*")); len(left) != 0 {
		t.Fatalf("temporary binary left on the server: %v", left)
	}
}

func TestScanRejectsOptionLikeTargets(t *testing.T) {
	o, _ := setup(t)
	for _, bad := range []string{"-oProxyCommand=touch /tmp/pwned", "host;id", "a b", "", "$(id)"} {
		if _, err := Scan(context.Background(), bad, o); err == nil || !strings.Contains(err.Error(), "invalid ssh target") {
			t.Errorf("target %q: err = %v", bad, err)
		}
	}
	if b, _ := os.ReadFile(os.Getenv("LOG")); len(b) != 0 {
		t.Fatalf("ssh was invoked for an invalid target: %s", b)
	}
}

func TestScanReportsRemoteFailure(t *testing.T) {
	o, _ := setup(t)
	if err := os.WriteFile(o.Self, []byte("#!/bin/sh\necho boom >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), "web-01", o); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want remote stderr", err)
	}
}
