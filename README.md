# nids-go

Un système de détection d'intrusion réseau (NIDS) léger écrit en Go. Il capture le trafic réseau en temps réel, analyse les paquets et génère des alertes en cas d'activité suspecte.

## Fonctionnalités

- Détection de **port scan** (5+ ports en 10s → WARNING, 15+ → CRITICAL)
- Détection de **SYN flood** (100+ paquets SYN purs en 5s)
- Détection de **brute force** sur SSH, Telnet, FTP, RDP, VNC (20+ connexions en 30s)
- Détection de **UDP flood** (200+ paquets en 5s)
- Détection de **ping sweep** ICMP (4+ hôtes en 10s → WARNING, 10+ → CRITICAL)
- Analyse de **payload** par signatures regex (injections SQL, XSS, reverse shells, scanners...)
- Journalisation des alertes en JSON avec rotation automatique à 10 MB

---

## Prérequis système

### Linux (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y golang libpcap-dev
```

### macOS

```bash
brew install go
# libpcap est inclus par défaut sur macOS
```

### Windows

> ⚠️ Windows n'est pas supporté nativement. Utiliser WSL2 avec Ubuntu.

Vérifier que Go >= 1.22 est installé :

```bash
go version
```

---

## Installation

```bash
git clone https://github.com/Saifeddine27/nids-go.git
cd nids-go
make setup
```

## Compilation

```bash
make build
```

Le binaire est généré dans `bin/nids`.

## Utilisation

```bash
make run
```

ou manuellement :

```bash
sudo ./bin/nids
```

> `sudo` est requis pour la capture de paquets réseau (accès raw socket).

Au démarrage, le programme liste les interfaces réseau disponibles et demande laquelle écouter :

```
🌐 Interfaces réseau disponibles :
  [0] eth0 (Ethernet)
  [1] lo (Loopback)
  [2] wlan0 (Wi-Fi)

👉 Entrez le nom de l'interface à écouter (ex: eth0, lo, wlan0) ou 'any' pour toutes :
```

Entrer le nom de l'interface souhaitée (ex: `eth0`) ou `any` pour capturer sur toutes les interfaces.

---

## Alertes

Les alertes s'affichent dans le terminal en temps réel :

```
[!] CRITICAL | PORT_SCAN      | 192.168.1.42 | 17 ports uniques ciblés en moins de 10s
[!] CRITICAL | SYN_FLOOD      | 10.0.0.5     | 103 paquets SYN en moins de 5s
[-] WARNING  | PING_SWEEP     | 192.168.1.10 | 5 hôtes uniques pingués en moins de 10s
[!] CRITICAL | SCANNER_SQLMAP | 192.168.1.33 | Signature détectée : User-Agent sqlmap
```

Elles sont aussi enregistrées dans `alerts.json` (format JSON Lines). Le fichier est automatiquement archivé sous `alerts_YYYYMMDD_HHMMSS.json` dès qu'il dépasse 10 MB.

---

## Signatures de détection (payload)

| Catégorie | Règles |
|---|---|
| Injection SQL | `SQL_INJECTION_UNION`, `SQL_INJECTION_DROP`, `SQL_INJECTION_OR`, `SQL_INJECTION_SLEEP` |
| Path Traversal | `PATH_TRAVERSAL`, `PATH_TRAVERSAL_ENCODED` |
| Injection de commandes | `CMD_INJECTION_SHELL`, `CMD_INJECTION_WGET_CURL` |
| XSS | `XSS_SCRIPT_TAG`, `XSS_EVENT_HANDLER`, `XSS_JAVASCRIPT_URI` |
| Scanners offensifs | `SCANNER_NMAP`, `SCANNER_NIKTO`, `SCANNER_SQLMAP`, `SCANNER_METASPLOIT` |
| Shellcode / Malware | `SHELLCODE_NOP_SLED`, `BASE64_POWERSHELL`, `REVERSE_SHELL_NC` |
| Credentials en clair | `FTP_CREDENTIALS`, `HTTP_AUTH_BASIC` |

Les règles sont définies dans `rules/rules.yaml` et peuvent être modifiées ou étendues sans recompiler.

---

## Structure du projet

```
nids-go/
├── cmd/nids/          # Point d'entrée principal
├── internal/
│   ├── alert/         # Journalisation des alertes (JSON + rotation)
│   ├── capture/       # Capture de paquets (libpcap)
│   ├── config/        # Chargement de la configuration YAML
│   ├── engine/        # Moteur de détection (règles + heuristiques)
│   ├── filter/        # Filtrage du trafic bruit (DNS, DHCP, NTP...)
│   └── parser/        # Parsing des paquets réseau
├── rules/
│   └── rules.yaml     # Signatures de détection
└── Makefile
```

---

## Dépendances Go

| Package | Version | Rôle |
|---|---|---|
| `github.com/google/gopacket` | v1.1.19 | Capture et parsing de paquets réseau |
| `gopkg.in/yaml.v3` | v3.0.1 | Lecture des règles YAML |

Installées automatiquement par `make setup`.

## Nettoyage

```bash
make clean
```

Supprime le binaire compilé dans `bin/`.
