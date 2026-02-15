package html

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetTemplate_Success(t *testing.T) {
	// Create a temp dir with test templates
	tmpDir := t.TempDir()
	SetTemplateDir(tmpDir)
	defer SetTemplateDir("/usr/share/keycloak-ssh-auth/templates")

	content := "<html><body>Success!</body></html>"
	err := os.WriteFile(filepath.Join(tmpDir, "success.html"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write test template: %v", err)
	}

	result, err := GetTemplate("success.html")
	if err != nil {
		t.Fatalf("GetTemplate failed: %v", err)
	}
	if result != content {
		t.Errorf("expected '%s', got '%s'", content, result)
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	SetTemplateDir(t.TempDir())
	defer SetTemplateDir("/usr/share/keycloak-ssh-auth/templates")

	_, err := GetTemplate("nonexistent.html")
	if err == nil {
		t.Error("should fail for nonexistent template")
	}
}

func TestSetTemplateDir(t *testing.T) {
	original := templateDir
	defer SetTemplateDir(original)

	SetTemplateDir("/custom/path")
	if templateDir != "/custom/path" {
		t.Errorf("expected '/custom/path', got '%s'", templateDir)
	}
}
