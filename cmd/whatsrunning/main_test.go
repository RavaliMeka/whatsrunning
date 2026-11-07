package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileRefusesSymlinkAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "report.html")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(link, func(w io.Writer) error { _, err := io.WriteString(w, "x"); return err }); err == nil {
		t.Fatal("followed a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("symlink target was modified")
	}

	out := filepath.Join(dir, "new.html")
	if err := writeFile(out, func(w io.Writer) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("report mode %v, want 0600", st.Mode().Perm())
	}
}
