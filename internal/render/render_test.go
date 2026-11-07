package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
)

func TestHTMLEscapesScannedValues(t *testing.T) {
	evil := `</script><img src=x onerror=alert(1)>`
	g := graph.New()
	g.Host.Hostname = evil
	g.AddNode(&graph.Node{ID: "ctr:x", Kind: graph.KindContainer, Name: evil})
	var buf bytes.Buffer
	if err := HTML(&buf, Report{Graph: g}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<img src=x") {
		t.Fatal("scanned value was written as raw HTML")
	}
	_, rest, _ := strings.Cut(out, "<script>")
	script, _, _ := strings.Cut(rest, "</script>")
	sum := sha256.Sum256([]byte(script))
	if !strings.Contains(out, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatal("CSP does not pin the rendered script")
	}
}
