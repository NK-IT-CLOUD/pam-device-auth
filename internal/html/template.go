package html

import (
    "os"
    "path/filepath"
)

var templateDir = "/usr/share/keycloak-ssh-auth/templates"

func GetTemplate(name string) (string, error) {
    path := filepath.Join(templateDir, name)
    content, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }
    return string(content), nil
}

// SetTemplateDir allows changing the template directory (useful for testing)
func SetTemplateDir(dir string) {
    templateDir = dir
}
