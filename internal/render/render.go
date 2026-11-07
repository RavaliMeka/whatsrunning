// Package render writes the HTML map, the JSON report and the terminal summary.
package render

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"strings"

	"github.com/RavaliMeka/whatsrunning/internal/graph"
	"github.com/RavaliMeka/whatsrunning/internal/rules"
)

//go:embed map.html
var mapTemplate string

type Report struct {
	Graph    *graph.Graph    `json:"graph"`
	Findings []rules.Finding `json:"findings"`
}

// HTML renders a single self-contained page. Scanned values reach the page only
// as JSON (json.Marshal escapes <, > and &), and the CSP allows exactly this
// script by hash and no network access at all.
func HTML(w io.Writer, r Report) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	head, rest, _ := strings.Cut(mapTemplate, "<script>")
	script, tail, _ := strings.Cut(rest, "</script>")
	script = strings.Replace(script, "__DATA__", string(data), 1)
	sum := sha256.Sum256([]byte(script))
	head = strings.Replace(head, "__HOST__", html.EscapeString(r.Graph.Host.Hostname), 1)
	head = strings.Replace(head, "__SCRIPT_HASH__", base64.StdEncoding.EncodeToString(sum[:]), 1)
	_, err = io.WriteString(w, head+"<script>"+script+"</script>"+tail)
	return err
}

func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var sevColor = map[rules.Severity]string{rules.Critical: "1;31", rules.High: "1;33", rules.Medium: "33", rules.Low: "2"}

func UseColor() bool {
	st, err := os.Stdout.Stat()
	return os.Getenv("NO_COLOR") == "" && err == nil && st.Mode()&os.ModeCharDevice != 0
}

func Terminal(w io.Writer, r Report, color, verbose bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return "\033[" + code + "m" + s + "\033[0m"
	}
	g := r.Graph
	count := map[graph.Kind]int{}
	running, public := 0, 0
	for _, n := range g.Nodes {
		count[n.Kind]++
		if n.Attrs["running"] == "true" {
			running++
		}
	}
	for _, e := range g.Edges {
		if n := g.Node(e.To); e.Public && n != nil && n.Kind != graph.KindDomain {
			public++
		}
	}
	where := g.Host.Hostname
	if g.Host.OS != "" {
		where += " · " + g.Host.OS
	}
	fmt.Fprintf(w, "\n%s  %s\n", c("1", "whatsrunning"), c("2", where))
	fmt.Fprintf(w, "  %d containers (%d running) · %d host services · %d volumes · %d public ports\n\n",
		count[graph.KindContainer], running, count[graph.KindProcess], count[graph.KindVolume], public)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  "+c("32", "No issues found."))
	} else {
		var parts []string
		counts := rules.Counts(r.Findings)
		for _, s := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
			if counts[s] > 0 {
				parts = append(parts, c(sevColor[s], fmt.Sprintf("%d %s", counts[s], s)))
			}
		}
		fmt.Fprintf(w, "  Findings: %s\n\n", strings.Join(parts, ", "))
		for _, f := range r.Findings {
			if verbose || f.Severity != rules.Low {
				fmt.Fprintf(w, "  %s %s\n           %s\n", c(sevColor[f.Severity], fmt.Sprintf("%-8s", strings.ToUpper(string(f.Severity)))), f.Title, c("2", "fix: "+f.Fix))
			}
		}
		if !verbose && counts[rules.Low] > 0 {
			fmt.Fprintf(w, "  %s\n", c("2", fmt.Sprintf("+ %d low-severity findings (see the map, or use -v)", counts[rules.Low])))
		}
	}
	for _, wn := range g.Warnings {
		fmt.Fprintf(w, "\n  %s", c("2", "note: "+wn))
	}
	fmt.Fprintln(w)
}
