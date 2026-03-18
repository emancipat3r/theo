# theo

Stateless Linux threat triage tool. SSHs into target hosts concurrently, escalates to root, runs point-in-time IoC heuristics, introspects Docker/Podman containers, and classifies findings by severity — all from a single compiled binary.

## Install

```bash
go build -o theo .
```

Cross-compile for a different target:

```bash
GOOS=linux GOARCH=amd64 go build -o theo .
```

## Usage

```bash
./theo
```

An interactive form prompts for:

- **Target IPs** — comma-separated list of hosts to triage
- **SSH Port** — defaults to 22
- **SSH Username** — does not need to be root
- **Auth method** — password, SSH key, or both
- **SSH Password** — echo-less input
- **SSH Key Path** — defaults to `~/.ssh/id_rsa`
- **Sudo Password** — defaults to SSH password; leave blank for NOPASSWD sudo

## How privilege escalation works

1. Logs in as the provided user via SSH
2. Runs `id -u` to check if already root
3. If root — runs triage directly
4. If not root — tries `sudo -n` (passwordless) first, then falls back to `sudo -S` with the password piped via stdin (never passed in the command string)

## What it checks

### Host-level checks

| Check | Category | What it detects |
|---|---|---|
| MEMEXEC | Malware | Executable files in `/dev/shm`, `/tmp`, `/var/tmp` |
| DELETED | Malware | Running processes whose binary has been deleted from disk |
| HIDDEN | Malware | Hidden files in writable temp directories |
| UID0 | Backdoor | Non-root accounts with UID 0 |
| LDPRELOAD | Rootkit | Entries in `/etc/ld.so.preload` (userland rootkit hooking) |
| PROCHIDE | Rootkit | Process hiding — compares `ps` PID count vs `/proc` entries |
| TAINTED | Rootkit | Kernel taint flags (unsigned/out-of-tree module loaded) |
| KMOD | Rootkit | Loaded kernel modules (flags known rootkit module names) |
| IMMUTABLE | Rootkit | Files with immutable attribute set in `/etc`, `/tmp`, `/var/tmp` |
| MODBINS | Tampering | System binaries modified in the last 7 days |
| SUID | Priv Esc | SUID/SGID binaries outside standard system paths |
| CRON | Persistence | Crontabs and cron directories for all users |
| TIMERS | Persistence | Systemd timers |
| ATJOBS | Persistence | Scheduled `at` jobs |
| SHELLINIT | Persistence | Suspicious commands in `.bashrc`, `.profile`, `/etc/profile.d/` |
| RCLOCAL | Persistence | Non-comment entries in `/etc/rc.local`, non-standard init.d scripts |
| PAM | Persistence | Recently modified PAM configs or modules |
| AUTHKEYS | Persistence | SSH authorized_keys for all users |
| SERVICES | Recon | Running systemd services (flags crypto-miner patterns) |
| LISTEN | Recon | Listening TCP ports with process info |
| OUTBOUND | C2/Exfil | Established outbound TCP connections (flags suspicious ports) |
| DNSCONF | C2/Exfil | DNS resolver configuration |
| IPTABLES | Evasion | Non-default iptables rules |
| HISTORY | Evasion | Bash history anomalies (symlinked, missing, empty) |
| SHADOWPERMS | Credential | `/etc/shadow` permission check |
| KNOWNHOSTS | Lateral | SSH known_hosts entries (maps lateral movement paths) |
| FAILEDAUTH | Brute Force | Failed SSH logins in the last 24 hours |
| LOGCHECK | Anti-Forensics | Empty or suspiciously recent log files |
| NETNS | Context | Network namespaces |
| CONTAINERENV | Context | Whether the host itself is running inside a container |

### Container-level checks (Docker / Podman)

If a container runtime is detected, theo enumerates all running containers and runs two passes:

**Host-side inspection** (`docker inspect`):
- Privileged mode (CRITICAL — full host access)
- Individual dangerous capabilities: `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`, `NET_ADMIN`
- Host network / PID namespace sharing
- Bind mounts — flags docker socket (CRITICAL), host root filesystem (CRITICAL), sensitive paths like `/etc`, `/root`, `/home` (HIGH)

**In-container triage** (`docker exec`):
- Running processes (falls back to `/proc` if `ps` is unavailable)
- Listening ports (`ss` / `netstat` / `/proc/net/tcp`)
- Executable files in temp dirs
- Hidden files in temp dirs
- Non-root UID 0 accounts
- Crontabs
- Docker socket accessible from inside container (container escape vector)
- Kubernetes service account tokens

The in-container script uses `sh` and guards every command with `command -v` so it degrades gracefully in minimal/alpine/distroless images. If `sh` isn't available at all (e.g. distroless), it falls back to `docker top` from the host side.

## Automated analysis

Findings are not just collected — they are analyzed and classified:

### Severity levels

| Level | Meaning | Example |
|---|---|---|
| **CRITICAL** | Definitive IoC — likely compromised | Deleted running binary, UID 0 backdoor, `ld.so.preload` entry, hidden processes, rootkit kernel module |
| **HIGH** | Strong indicator — needs investigation | Executable in `/tmp`, non-standard SUID, suspicious shell init, PAM modification, privileged container |
| **MEDIUM** | Worth reviewing | Crontab entries, modified system binaries, at jobs, sensitive container mounts, empty log files |
| **LOW** | Context / noise | Failed auth attempts, iptables rules, outbound connections |
| **INFO** | Baseline data | Running services, listening ports, kernel modules, DNS config |

### Pattern matching

The analysis layer upgrades severity based on content, not just which check produced the finding:

- **Rootkit module names** (diamorphine, reptile, etc.) in KMOD → CRITICAL
- **Crypto-miner service names** (xmrig, minerd) in SERVICES → HIGH
- **Suspicious outbound ports** (4444, 1337, 31337) in OUTBOUND → HIGH
- **Process hiding** (ps/proc PID count mismatch > 5) → CRITICAL
- **Kernel tainted** (non-zero) → HIGH
- **History evasion** (symlinked to /dev/null) → CRITICAL; missing/empty for root → HIGH
- **Shadow permissions** (world-readable) → CRITICAL; wrong perms → HIGH

### Host verdict

Each host gets an overall verdict based on the highest severity finding:

| Verdict | Condition |
|---|---|
| `COMPROMISED` | Any CRITICAL finding |
| `SUSPICIOUS` | Any HIGH finding |
| `REVIEW` | Any MEDIUM finding |
| `CLEAN` | Only LOW/INFO findings |

## Output

### Terminal

- Summary table: host, status, verdict, privilege method, container count, finding counts by severity (`3C 2H 5M 1L 12I`)
- Detail view: only MEDIUM+ findings shown, grouped by severity with color coding
- INFO-level findings are counted but not printed (see JSON report for full data)

### JSON report

Full structured report saved to `triage_YYYYMMDD_HHMMSS.json` with every finding at all severity levels. Useful for:
- Diffing between runs to detect changes over time
- Feeding into other tools or dashboards
- Archival / audit trail

## Dependencies

- [charmbracelet/huh](https://github.com/charmbracelet/huh) — interactive form
- [charmbracelet/log](https://github.com/charmbracelet/log) — runtime logging
- [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) — styled terminal output
- [x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) — SSH client
