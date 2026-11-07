// Package nginx reads nginx configuration and adds the domains it serves, and
// where each one routes, to the graph.
package nginx

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxFileSize = 1 << 20
	maxFiles    = 256
	maxDepth    = 16
)

type directive struct {
	name  string
	args  []string
	block []directive
}

// tokenize splits nginx syntax into words and the punctuation { } ;
func tokenize(src string) []string {
	var toks []string
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, string(c))
			i++
		case c == '"' || c == '\'':
			j := i + 1
			var b strings.Builder
			for j < len(src) && src[j] != c {
				if src[j] == '\\' && j+1 < len(src) {
					j++
				}
				b.WriteByte(src[j])
				j++
			}
			toks = append(toks, b.String())
			i = j + 1
		default:
			j := i
			for j < len(src) && !strings.ContainsRune(" \t\r\n{};#", rune(src[j])) {
				j++
			}
			toks = append(toks, src[i:j])
			i = j
		}
	}
	return toks
}

// loader reads files through resolve, which maps a path as nginx sees it to a
// readable host path (identity for a host install, bind mounts for a container).
type loader struct {
	resolve func(string) (string, bool)
	prefix  string
	files   int
}

func (l *loader) load(path string, depth int) ([]directive, error) {
	if depth > maxDepth || l.files >= maxFiles {
		return nil, fmt.Errorf("nginx: include depth or file limit reached at %s", path)
	}
	host, ok := l.resolve(path)
	if !ok {
		return nil, fmt.Errorf("nginx: %s is not readable from the host", path)
	}
	f, err := os.Open(host)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize))
	if err != nil {
		return nil, err
	}
	l.files++
	toks := tokenize(string(b))
	ds, _, err := l.parse(toks, 0, depth)
	return ds, err
}

func (l *loader) parse(toks []string, i, depth int) ([]directive, int, error) {
	var out []directive
	for i < len(toks) {
		if toks[i] == "}" {
			return out, i + 1, nil
		}
		d := directive{name: toks[i]}
		i++
		for i < len(toks) && toks[i] != ";" && toks[i] != "{" && toks[i] != "}" {
			d.args = append(d.args, toks[i])
			i++
		}
		if i < len(toks) && toks[i] == "{" {
			var err error
			if d.block, i, err = l.parse(toks, i+1, depth); err != nil {
				return out, i, err
			}
		} else {
			i++ // ;
		}
		if d.name == "include" && len(d.args) == 1 {
			out = append(out, l.include(d.args[0], depth)...)
			continue
		}
		out = append(out, d)
	}
	return out, i, nil
}

// include expands a glob relative to the nginx prefix. Unreadable files are
// skipped rather than failing the whole config, as nginx -T would show them.
func (l *loader) include(pattern string, depth int) []directive {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(l.prefix, pattern)
	}
	host, ok := l.resolve(pattern)
	if !ok {
		return nil
	}
	matches, _ := filepath.Glob(host)
	sort.Strings(matches)
	var out []directive
	for _, m := range matches {
		rel, err := filepath.Rel(host[:len(host)-len(filepath.Base(host))], m)
		if err != nil {
			continue
		}
		ds, _ := l.load(filepath.Join(filepath.Dir(pattern), rel), depth+1)
		out = append(out, ds...)
	}
	return out
}

func walk(ds []directive, fn func(directive)) {
	for _, d := range ds {
		fn(d)
		walk(d.block, fn)
	}
}
