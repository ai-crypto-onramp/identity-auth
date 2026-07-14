package internal

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestGenRBACBundleMatches runs cmd/gen-rbac-bundle and verifies the generated
// role_permissions block mirrors the canonical rolePermissions map in rbac.go.
func TestGenRBACBundleMatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bundle generation in short mode")
	}
	tmp := t.TempDir()
	out := filepath.Join(tmp, "rbac.rego")
	cmd := exec.Command("go", "run", "./cmd/gen-rbac-bundle", "-out", out)
	cmd.Dir = ".."
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run gen-rbac-bundle: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	body := string(data)
	for role, perms := range rolePermissions {
		if !strings.Contains(body, role) {
			t.Errorf("bundle missing role %q", role)
			continue
		}
		sorted := append([]string(nil), perms...)
		sort.Strings(sorted)
		for _, p := range sorted {
			if !strings.Contains(body, p) {
				t.Errorf("bundle missing permission %q for role %q", p, role)
			}
		}
	}
	if !strings.Contains(body, "package identity_auth") {
		t.Error("bundle missing package declaration")
	}
	if !strings.Contains(body, "allow {") {
		t.Error("bundle missing allow rule")
	}
	if !strings.Contains(body, "scope_matches") {
		t.Error("bundle missing scope_matches rule")
	}
}