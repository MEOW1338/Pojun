package server

import (
	"os"
	"path/filepath"
	"testing"
)

// A workspace symlink must not become a read/write/delete escape hatch.
func TestWorkspaceResolveRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := &Server{m: &Manager{dir: base}}
	for _, rel := range []string{"link/secret", "link/new-file"} {
		if _, ok := s.wsResolve(rel); ok {
			t.Fatalf("workspace escape via %q was accepted", rel)
		}
	}
	if abs, ok := s.wsResolve("safe/new-file"); !ok || !pathWithin(base, abs) {
		t.Fatalf("safe path rejected: abs=%q ok=%v", abs, ok)
	}
	if abs, ok := s.wsResolve(""); !ok || filepath.Clean(abs) != filepath.Clean(base) {
		t.Fatalf("workspace root rejected: abs=%q ok=%v", abs, ok)
	}
}
