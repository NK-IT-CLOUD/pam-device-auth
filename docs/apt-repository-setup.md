# APT Repository Setup for pam-device-auth

Eigenes APT Repository aufsetzen, damit User per `apt install pam-device-auth` installieren und per `apt upgrade` updaten koennen.

## Ziel

```bash
# User fuegt Repo einmalig hinzu:
curl -fsSL https://repo.nk-it.cloud/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nk-it.gpg
echo "deb [signed-by=/etc/apt/keyrings/nk-it.gpg] https://repo.nk-it.cloud/apt stable main" | sudo tee /etc/apt/sources.list.d/nk-it.list

# Danach:
sudo apt update
sudo apt install pam-device-auth    # Install
sudo apt upgrade pam-device-auth    # Update
```

## Voraussetzungen

### Infrastruktur

| Komponente | Zweck | Status |
|-----------|-------|--------|
| Webserver (Caddy/Nginx) | Repo per HTTPS hosten | vorhanden (nk-it.cloud Infra) |
| Domain/Subdomain | z.B. `repo.nk-it.cloud` | DNS Eintrag noetig |
| GPG Key | Pakete signieren | muss erstellt werden |
| `reprepro` oder `aptly` | Repo-Verwaltung (Pakete hinzufuegen/entfernen) | muss installiert werden |
| CI/CD Pipeline | Automatisch build -> sign -> upload bei Release | Gitea Actions oder Script |
| Storage | ~100MB fuer Repo + Pakete | minimal |

### Software auf dem Repo-Server

```bash
sudo apt install reprepro gnupg
```

## Architektur

```
Gitea (git push / tag)
  |
  v
CI/CD Pipeline
  |
  +-- make release          # Build .deb
  +-- dpkg-sig --sign       # Signieren mit GPG Key
  +-- reprepro includedeb   # In Repo aufnehmen
  |
  v
Webserver (repo.nk-it.cloud)
  |
  +-- /apt/dists/stable/main/binary-amd64/
  +-- /apt/pool/main/p/pam-device-auth/
  +-- /gpg.key               # Oeffentlicher GPG Key
  |
  v
User: apt update && apt install pam-device-auth
```

## Schritte

### 1. GPG Key erstellen

Dedizierter Signing Key fuer das Repository (nicht persoenlicher Key):

```bash
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: NK-IT APT Repository
Name-Email: apt@nk-it.cloud
Expire-Date: 0
%no-protection
EOF

# Key-ID merken
gpg --list-keys apt@nk-it.cloud

# Oeffentlichen Key exportieren
gpg --armor --export apt@nk-it.cloud > gpg.key
```

### 2. reprepro Verzeichnisstruktur

```bash
mkdir -p /var/www/repo.nk-it.cloud/apt/conf

# Distribution konfigurieren
cat > /var/www/repo.nk-it.cloud/apt/conf/distributions <<EOF
Origin: NK-IT-CLOUD
Label: NK-IT APT Repository
Codename: stable
Architectures: amd64
Components: main
Description: NK-IT infrastructure packages
SignWith: apt@nk-it.cloud
EOF

# Optionen
cat > /var/www/repo.nk-it.cloud/apt/conf/options <<EOF
verbose
ask-passphrase
EOF

# GPG Key fuer User bereitstellen
cp gpg.key /var/www/repo.nk-it.cloud/gpg.key
```

### 3. Paket ins Repo aufnehmen

```bash
# Neues Paket hinzufuegen
reprepro -b /var/www/repo.nk-it.cloud/apt includedeb stable /path/to/pam-device-auth_0.3.1_amd64.deb

# Altes Paket entfernen (optional)
reprepro -b /var/www/repo.nk-it.cloud/apt remove stable pam-device-auth

# Repo-Inhalt anzeigen
reprepro -b /var/www/repo.nk-it.cloud/apt list stable
```

### 4. Webserver konfigurieren

Caddy Beispiel:

```
repo.nk-it.cloud {
    root * /var/www/repo.nk-it.cloud
    file_server {
        browse
    }
    header Content-Type application/octet-stream
    @deb path *.deb
    @gpg path *.key *.gpg
}
```

### 5. CI/CD Pipeline (Gitea Actions)

Bei jedem Git Tag automatisch:

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: make release

      - name: Sign
        run: dpkg-sig --sign builder build/packages/*.deb

      - name: Publish to APT repo
        run: |
          scp build/packages/*.deb repo-server:/tmp/
          ssh repo-server "reprepro -b /var/www/repo.nk-it.cloud/apt includedeb stable /tmp/pam-device-auth_*.deb"
```

### 6. User-seitige Installation

Einmalig:

```bash
# GPG Key importieren
curl -fsSL https://repo.nk-it.cloud/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nk-it.gpg

# Repo hinzufuegen
echo "deb [signed-by=/etc/apt/keyrings/nk-it.gpg] https://repo.nk-it.cloud/apt stable main" | sudo tee /etc/apt/sources.list.d/nk-it.list

# Installieren
sudo apt update
sudo apt install pam-device-auth
```

Updates kommen danach automatisch per `apt upgrade`.

## Optionale Erweiterungen

| Feature | Beschreibung |
|---------|-------------|
| Mehrere Pakete | Repo kann alle NK-IT .deb Pakete hosten (nicht nur pam-device-auth) |
| Multiple Distros | `stable`, `testing`, `unstable` Channels |
| Architectures | `arm64` Support hinzufuegen |
| Install-Script | `curl \| bash` Convenience-Script das Repo automatisch einrichtet |
| Paket-Pinning | Priority-Konfiguration damit eigene Pakete Vorrang haben |

## Aufwand

| Schritt | Geschaetzter Aufwand |
|---------|---------------------|
| GPG Key + reprepro Setup | 1-2 Stunden |
| Webserver/DNS Konfiguration | 1 Stunde |
| CI/CD Pipeline | 2-3 Stunden |
| Testen (install/upgrade/remove) | 1-2 Stunden |
| Dokumentation (README Update) | 30 Minuten |
| **Gesamt** | **~1 Tag** |
