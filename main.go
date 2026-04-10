package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/log"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Severity & Finding types
// ---------------------------------------------------------------------------

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type Finding struct {
	Check    string   `json:"check"`
	Detail   string   `json:"detail"`
	Severity Severity `json:"severity"`
}

type ContainerResult struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Image    string    `json:"image"`
	Findings []Finding `json:"findings"`
}

type HostResult struct {
	IP         string            `json:"ip"`
	Status     string            `json:"status"`
	Verdict    string            `json:"verdict"`
	RootMethod string            `json:"root_method"`
	Duration   string            `json:"duration"`
	Findings   []Finding         `json:"findings"`
	Containers []ContainerResult `json:"containers,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Default severity per check — baseline before analysis
// ---------------------------------------------------------------------------

var defaultSeverity = map[string]Severity{
	// Definitive IoC indicators
	"DELETED":      SevCritical,
	"UID0":         SevCritical,
	"LDPRELOAD":    SevCritical,
	"PROCHIDE":     SevCritical,
	"MEMEXEC":      SevHigh,
	"SUID":         SevHigh,
	"HIDDEN":       SevHigh,
	"SHELLINIT":    SevHigh,
	"PAM":          SevHigh,
	"IMMUTABLE":    SevHigh,
	"MODBINS":      SevMedium,
	"LOGCHECK":     SevMedium,
	"CRON":         SevMedium,
	"AUTHKEYS":     SevMedium,
	"RCLOCAL":      SevMedium,
	"ATJOBS":       SevMedium,
	"FAILEDAUTH":   SevLow,
	"IPTABLES":     SevLow,
	"OUTBOUND":     SevLow,
	"PKGVERIFY":    SevMedium,
	"PROCTREE":     SevInfo,
	"PROCMASQ":     SevMedium,
	"ORPHANBIN":    SevMedium,
	"PROCMEM":      SevMedium,
	"PROCENV":      SevHigh,
	"LOGGAP":       SevMedium,
	"ORPHANSVC":    SevMedium,
	"USERACCT":     SevInfo,
	"DNSLEAK":      SevMedium,
	"LISTENORPHAN": SevMedium,

	// Informational — context, not IoCs by default
	"SERVICES":     SevInfo,
	"LISTEN":       SevInfo,
	"KMOD":         SevInfo,
	"TIMERS":       SevInfo,
	"KNOWNHOSTS":   SevInfo,
	"DNSCONF":      SevInfo,
	"NETNS":        SevInfo,
	"CONTAINERENV": SevInfo,
	"TAINTED":      SevInfo,
	"SGIDDIR":      SevInfo,
	"HISTORY":      SevInfo,
	"SHADOWPERMS":  SevInfo,

	// Container findings
	"CONFIG":     SevHigh,
	"MOUNT":      SevMedium,
	"DOCKERSOCK": SevCritical,
	"K8S":        SevHigh,
	"PROCS":      SevInfo,
	"NET":        SevInfo,
	"EXEC":       SevHigh,
	"USERS":      SevCritical,
}

// Known rootkit kernel module names
var rootkitModules = map[string]bool{
	"diamorphine": true, "reptile": true, "sutekh": true,
	"jynx": true, "enyelkm": true, "adore-ng": true, "adore_ng": true,
	"knark": true, "azazel": true, "brootus": true, "heroin": true,
	"kbeast": true, "suterusu": true, "hiding": true,
}

// Dangerous container capabilities
var dangerousCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"SYS_RAWIO": true, "DAC_OVERRIDE": true, "DAC_READ_SEARCH": true,
	"NET_ADMIN": true,
}

var dockerSockAllowlist = []string{
	"homepage", "gethomepage/homepage",
	"deunhealth", "qmcgaw/deunhealth",
	"watchtower", "containrrr/watchtower",
	"portainer", "portainer/portainer",
	"dockge", "louislam/dockge",
	"docker-socket-proxy", "tecnativa/docker-socket-proxy",
	"diun", "crazymax/diun",
	"autoheal", "willfarrell/autoheal",
}

var containerCronRegex = regexp.MustCompile(`(/api/v[0-9]+/cron/|wget .* http://[a-z_-]+:[0-9]+/)`)

// Kernel taint bit descriptions (from kernel docs)
var taintFlags = map[int]string{
	0:  "proprietary module",
	1:  "module force-loaded",
	2:  "kernel is SMP but CPU not designed for SMP",
	3:  "module force-unloaded",
	4:  "MCE (machine check exception)",
	5:  "bad page referenced",
	6:  "user request via sysrq",
	7:  "ACPI table overridden",
	8:  "kernel issued warning",
	9:  "staging driver loaded",
	10: "workaround for platform firmware bug applied",
	11: "externally-built (out-of-tree) module loaded",
	12: "unsigned module loaded",
	13: "soft lockup occurred",
	14: "kernel live-patched",
	15: "auxiliary taint (distro-defined)",
	16: "randstruct plugin randomized layout",
	17: "in-kernel test module loaded",
}

// ---------------------------------------------------------------------------
// Helpers & Data structures for checks
// ---------------------------------------------------------------------------

func parseKV(detail, key string) string {
	prefix := key + "="
	for _, part := range strings.Fields(detail) {
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return ""
}

type procAnomalyRule struct {
	ParentContains []string
	ChildContains  []string
	Severity       Severity
	Tag            string
}

var procTreeRules = []procAnomalyRule{
	{
		ParentContains: []string{"apache", "httpd", "nginx", "lighttpd", "caddy", "tomcat"},
		ChildContains:  []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "python", "perl", "ruby"},
		Severity:       SevCritical,
		Tag:            "WEB SHELL: web server spawned interactive process",
	},
	{
		ParentContains: []string{"sshd"},
		ChildContains:  []string{"python", "perl", "ruby", "nc", "ncat", "socat"},
		Severity:       SevHigh,
		Tag:            "unusual sshd child process",
	},
}

var procMasqAllowed = []string{"busybox", "python", "perl", "node", "java"}
var orphanbinAllowed = []string{"docker-compose", "kubectl", "helm", "terraform", "packer", "vault", "consul", "go", "rustup", "cargo", "node", "npm", "pip", "pip3"}
var procMemJIT = []string{"java", "node", "python", "ruby", "dotnet", "mono", "chrome", "chromium", "firefox", "v8", "qemu", "containerd-shim"}
var orphanSvcAllowed = []string{"docker", "containerd", "tailscaled", "netbird", "cloudflare", "zerotier", "node_exporter", "prometheus", "grafana", "telegraf", "filebeat", "elastic-agent"}
var listenOrphanAllowed = []string{"docker-proxy", "containerd", "kubelet", "node_exporter", "prometheus", "grafana-server", "caddy", "minio", "tailscaled", "netbird"}

// ---------------------------------------------------------------------------
// Analysis — upgrades/downgrades severity based on content
// ---------------------------------------------------------------------------

func analyzeFinding(f *Finding) {
	switch f.Check {
	case "PKGVERIFY":
		if strings.Contains(f.Detail, "[CONFFILE]") {
			f.Severity = SevInfo
		} else if strings.Contains(f.Detail, "[HASH_MISMATCH]") {
			f.Severity = SevHigh
		}

	case "PROCTREE":
		exe := parseKV(f.Detail, "exe")
		pexe := parseKV(f.Detail, "pexe")
		uid := parseKV(f.Detail, "uid")

		if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/dev/shm/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/run/user/") {
			f.Severity = SevHigh
			f.Detail += " — executable in temp directory"
		} else if uid == "0" && !strings.HasPrefix(exe, "/usr/") && !strings.HasPrefix(exe, "/bin/") && !strings.HasPrefix(exe, "/sbin/") && !strings.HasPrefix(exe, "/lib/") && !strings.HasPrefix(exe, "/opt/") {
			f.Severity = SevMedium
			f.Detail += " — root process from non-standard path"
		} else {
			for _, rule := range procTreeRules {
				pMatch := false
				for _, p := range rule.ParentContains {
					if strings.Contains(pexe, p) {
						pMatch = true
						break
					}
				}
				if !pMatch {
					continue
				}
				cMatch := false
				for _, c := range rule.ChildContains {
					if strings.Contains(exe, c) {
						cMatch = true
						break
					}
				}
				if cMatch {
					f.Severity = rule.Severity
					f.Detail += " — " + rule.Tag
					break
				}
			}
		}

	case "PROCMASQ":
		exe := parseKV(f.Detail, "exe")
		cmdline := parseKV(f.Detail, "cmdline")
		cmd0 := strings.Fields(cmdline)

		if len(cmd0) > 0 {

		}

		if strings.Contains(exe, "/tmp/") || strings.Contains(exe, "/dev/shm/") || strings.Contains(exe, "/var/tmp/") || strings.Contains(exe, "(deleted)") {
			f.Severity = SevCritical
			f.Detail += " [MASQUERADE: temp/deleted binary mismatched]"
		} else if strings.HasPrefix(cmdline, "[k") && exe != "" {
			f.Severity = SevCritical
			f.Detail += " [MASQUERADE: fake kernel thread]"
		} else {
			allowed := false
			for _, al := range procMasqAllowed {
				if strings.Contains(exe, al) {
					if al == "java" && strings.Contains(cmdline, "-jar") {
						allowed = true
						break
					}
					if al == "node" && strings.Contains(cmdline, ".js") {
						allowed = true
						break
					}
					if al == "python" || al == "perl" || al == "busybox" {
						allowed = true
						break
					}
				}
			}
			if allowed {
				f.Severity = SevInfo
			}
		}

	case "ORPHANBIN":
		if strings.HasPrefix(f.Detail, "/usr/local/") {
			f.Severity = SevInfo
		} else if strings.HasPrefix(f.Detail, "/usr/bin") || strings.HasPrefix(f.Detail, "/usr/sbin") {
			base := filepath.Base(strings.Fields(f.Detail)[0])
			allowed := false
			for _, al := range orphanbinAllowed {
				if base == al {
					allowed = true
					break
				}
			}
			if allowed {
				f.Severity = SevInfo
			}
		}

	case "PROCMEM":
		anonStr := parseKV(f.Detail, "anon_rwx")
		exe := parseKV(f.Detail, "exe")
		if n, err := strconv.Atoi(anonStr); err == nil {
			if n > 50 {
				f.Severity = SevCritical
			} else if n > 10 {
				f.Severity = SevHigh
			}
			isJIT := false
			for _, jit := range procMemJIT {
				if strings.Contains(exe, jit) {
					isJIT = true
					break
				}
			}
			if isJIT {
				if f.Severity == SevCritical {
					f.Severity = SevHigh
				} else if f.Severity == SevHigh {
					f.Severity = SevMedium
				} else if f.Severity == SevMedium || n <= 3 {
					f.Severity = SevInfo
				}
			}
			if n <= 3 && isJIT {
				f.Severity = SevInfo
			}
		}

	case "PROCENV":
		if strings.Contains(f.Detail, "LD_PRELOAD=/tmp/") || strings.Contains(f.Detail, "LD_PRELOAD=/dev/shm/") || strings.Contains(f.Detail, "LD_PRELOAD=/var/tmp/") || strings.Contains(f.Detail, "LD_PRELOAD=.") {
			f.Severity = SevCritical
		} else if strings.Contains(f.Detail, "LD_PRELOAD=/usr/lib") || strings.Contains(f.Detail, "LD_PRELOAD=/lib") || strings.Contains(f.Detail, "LD_PRELOAD=/usr/lib64") {
			f.Severity = SevMedium
		} else if strings.HasSuffix(f.Detail, "LD_PRELOAD=") {
			f.Severity = SevInfo
		}

	case "LOGGAP":
		if strings.Contains(f.Detail, "gap=") {
			gapStr := ""
			parts := strings.Split(f.Detail, "gap=")
			if len(parts) == 2 {
				gapStr = strings.Split(parts[1], "s")[0]
			}
			if gap, err := strconv.Atoi(gapStr); err == nil {
				if gap > 86400 {
					f.Severity = SevHigh
				}
			}
		} else if strings.Contains(f.Detail, "rate=") {
			f.Severity = SevInfo
		}

	case "ORPHANSVC":
		allowed := false
		for _, svc := range orphanSvcAllowed {
			if strings.Contains(f.Detail, svc) {
				allowed = true
				break
			}
		}
		if allowed {
			f.Severity = SevInfo
		} else {
			if strings.Contains(f.Detail, "path=/etc/systemd/system/") {
				f.Detail += " [USER_CREATED_SYSTEMD_DIR]"
			}
		}

	case "USERACCT":
		neverLogged := parseKV(f.Detail, "never_logged") == "1"
		sudoer := parseKV(f.Detail, "sudoer") == "true"
		uidStr := parseKV(f.Detail, "uid")
		uid, _ := strconv.Atoi(uidStr)
		hasHome := parseKV(f.Detail, "home_exists") == "true"

		if neverLogged && sudoer {
			f.Severity = SevHigh
			f.Detail += " [dormant sudoer account]"
		} else if neverLogged && uid >= 1000 && !hasHome {
			f.Severity = SevMedium
			f.Detail += " [phantom user — no home, never logged in]"
		} else if strings.HasPrefix(f.Detail, "/etc/sudoers.d/") && strings.Contains(f.Detail, "[UNPACKAGED]") {
			f.Severity = SevMedium
			f.Detail += " [unpackaged sudoers drop-in]"
		}

	case "DNSLEAK":
		if strings.Contains(f.Detail, "[NON_CONFIGURED_DNS=") {
			if strings.Contains(f.Detail, "127.0.0.1") || strings.Contains(f.Detail, "127.0.0.53") || strings.Contains(f.Detail, "::1") {
				f.Severity = SevInfo
			}
		} else {
			f.Severity = SevInfo
		}

	case "LISTENORPHAN":
		exe := parseKV(f.Detail, "exe")
		if strings.HasPrefix(exe, "/usr/local/") || strings.HasPrefix(exe, "/opt/") || strings.HasPrefix(exe, "/home/") {
			f.Severity = SevLow
		} else if strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/dev/shm/") || strings.HasPrefix(exe, "/var/tmp/") {
			f.Severity = SevCritical
		} else {
			allowed := false
			for _, al := range listenOrphanAllowed {
				if strings.Contains(exe, al) {
					allowed = true
					break
				}
			}
			if allowed {
				f.Severity = SevInfo
			}
		}

	case "DELETED":
		// If dpkg confirms the binary's package was upgraded, this is a
		// stale process — not malware. Downgrade from CRITICAL to MEDIUM.
		if strings.Contains(f.Detail, "[PKG_UPGRADED=") {
			f.Severity = SevMedium
		}

	case "PROCHIDE":
		// ps=X proc=Y diff=Z — diff > 5 means processes are hidden
		for _, part := range strings.Fields(f.Detail) {
			if strings.HasPrefix(part, "diff=") {
				if n, err := strconv.Atoi(strings.TrimPrefix(part, "diff=")); err == nil {
					if n <= 5 {
						f.Severity = SevInfo // normal variance
					}
				}
			}
		}

	case "TAINTED":
		raw := strings.TrimSpace(f.Detail)
		// Extract the numeric taint value (may have [KNOWN_DRIVERS=...] appended)
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			break
		}
		taintStr := fields[0]
		if taintStr != "0" {
			if val, err := strconv.Atoi(taintStr); err == nil {
				var flags []string
				for bit := 0; bit < 18; bit++ {
					if val&(1<<bit) != 0 {
						if desc, ok := taintFlags[bit]; ok {
							flags = append(flags, desc)
						} else {
							flags = append(flags, fmt.Sprintf("bit%d", bit))
						}
					}
				}
				decoded := strings.Join(flags, ", ")
				if strings.Contains(raw, "[KNOWN_DRIVERS=") {
					// All out-of-tree modules are known drivers — not suspicious
					drivers := raw[strings.Index(raw, "[KNOWN_DRIVERS=")+15:]
					drivers = strings.TrimSuffix(drivers, "]")
					f.Detail = fmt.Sprintf("%s (%s) [KNOWN_DRIVERS=%s]", taintStr, decoded, drivers)
					f.Severity = SevInfo
				} else {
					f.Detail = fmt.Sprintf("%s (%s)", taintStr, decoded)
					f.Severity = SevHigh
				}
			} else {
				f.Severity = SevHigh
			}
		}

	case "HISTORY":
		if strings.Contains(f.Detail, "SYMLINKED") {
			f.Severity = SevCritical // deliberate evasion
		} else if strings.Contains(f.Detail, "MISSING") || strings.Contains(f.Detail, "EMPTY") {
			if strings.Contains(f.Detail, "[APPLIANCE_OS]") {
				// Appliance OSes (TrueNAS, pfSense, Proxmox, etc.) don't persist history
				f.Severity = SevInfo
			} else if strings.Contains(f.Detail, "/root") {
				f.Severity = SevHigh
			} else {
				f.Severity = SevMedium
			}
		}

	case "SHELLINIT":
		if strings.Contains(f.Detail, "SUSPICIOUS") {
			f.Severity = SevHigh
		} else {
			f.Severity = SevInfo // just listing profile.d files
		}

	case "KMOD":
		mod := strings.TrimSpace(strings.ToLower(f.Detail))
		if rootkitModules[mod] {
			f.Severity = SevCritical
		}

	case "SERVICES":
		lower := strings.ToLower(f.Detail)
		for _, suspicious := range []string{"xmrig", "minerd", "kworker", "cryptonight", "stratum"} {
			if strings.Contains(lower, suspicious) {
				f.Severity = SevHigh
				break
			}
		}

	case "OUTBOUND":
		// Flag connections to known suspicious ports
		for _, port := range []string{":4444 ", ":5555 ", ":6666 ", ":8888 ", ":9999 ",
			":1337 ", ":31337 ", ":4443 ", ":1234 "} {
			if strings.Contains(f.Detail, port) {
				f.Severity = SevHigh
				break
			}
		}

	case "FAILEDAUTH":
		if strings.HasPrefix(f.Detail, "TOTAL_FAILURES=") {
			countStr := strings.TrimPrefix(f.Detail, "TOTAL_FAILURES=")
			if count, err := strconv.Atoi(countStr); err == nil {
				if count > 100 {
					f.Severity = SevHigh
					f.Detail = fmt.Sprintf("%d failed auth attempts in 24h — possible brute force", count)
				} else if count > 20 {
					f.Severity = SevMedium
					f.Detail = fmt.Sprintf("%d failed auth attempts in 24h", count)
				} else {
					f.Severity = SevLow
					f.Detail = fmt.Sprintf("%d failed auth attempts in 24h", count)
				}
			}
		} else {
			f.Severity = SevLow
		}

	case "AUTHKEYS":
		// Header lines: "/path: keys=N age_days=X"
		// Key content lines: ssh-rsa/ssh-ed25519 ...
		if strings.Contains(f.Detail, "age_days=") {
			// Parse age — if not recently modified, downgrade to INFO
			for _, part := range strings.Fields(f.Detail) {
				if strings.HasPrefix(part, "age_days=") {
					if days, err := strconv.Atoi(strings.TrimPrefix(part, "age_days=")); err == nil {
						if days > 7 {
							f.Severity = SevInfo
						}
						// Recently modified stays MEDIUM
					}
				}
			}
		} else {
			// Key content lines are informational context
			f.Severity = SevInfo
		}

	case "MODBINS":
		// Binaries modified by a package upgrade are expected
		if strings.Contains(f.Detail, "[PKG_UPGRADED=") {
			f.Severity = SevInfo
		}

	case "CRON":
		// Downgrade standard distro cron scripts to INFO
		lower := strings.ToLower(f.Detail)
		for _, standard := range []string{
			"e2scrub_all", "sysstat", "apport", "apt-compat",
			"dpkg", "logrotate", "man-db", "popularity-contest",
			"update-notifier-common", "google-chrome",
			"0hourly", "0anacron", "raid-check",
			"certbot", "exim4", "exim4-base", "anacron",
			"bsdmainutils", "mlocate", "plocate",
		} {
			if strings.Contains(lower, standard) {
				f.Severity = SevInfo
				break
			}
		}
		if containerCronRegex.MatchString(lower) {
			f.Severity = SevInfo
		}
		// Alpine default periodic crontabs (present in every Alpine container)
		if strings.Contains(f.Detail, "run-parts /etc/periodic/") {
			f.Severity = SevInfo
		}
		// Placeholder files
		if strings.Contains(lower, ".placeholder") {
			f.Severity = SevInfo
		}

	case "RCLOCAL":
		if strings.Contains(f.Detail, "[PKG_OWNED]") {
			f.Severity = SevInfo
		}

	case "LOGCHECK":
		// Empty logs that are normal: apport, alternatives, rotated mail/spooler logs
		lower := strings.ToLower(f.Detail)
		if strings.Contains(lower, "apport") || strings.Contains(lower, "alternatives") ||
			strings.Contains(lower, "maillog") || strings.Contains(lower, "spooler") ||
			strings.Contains(lower, "boot.log") {
			f.Severity = SevInfo
		}
		// RHEL-style rotated logs with date suffixes (e.g., spooler-20260222)
		for _, base := range []string{"maillog-", "spooler-", "secure-", "messages-", "cron-"} {
			if strings.Contains(lower, base) {
				f.Severity = SevInfo
				break
			}
		}

	case "PAM":
		// PAM files owned by a distro package are not suspicious
		if strings.Contains(f.Detail, "[PKG_OWNED]") {
			f.Severity = SevInfo
		}

	case "SHADOWPERMS":
		// Normal: -rw-r----- or -rw------- or ---------- (mode 000, RHEL default)
		if strings.HasPrefix(f.Detail, "-rw-r-----") || strings.HasPrefix(f.Detail, "-rw-------") || strings.HasPrefix(f.Detail, "----------") {
			f.Severity = SevInfo
		} else if strings.Contains(f.Detail, "rw-rw") || strings.Contains(f.Detail, "r--r--r--") {
			f.Severity = SevCritical // world or group readable
		} else {
			f.Severity = SevHigh
		}

	case "HIDDEN":
		// Python tempfile .lock files are normal application behavior
		if strings.HasSuffix(f.Detail, "/.lock") && strings.Contains(f.Detail, "/tmp/tmp") {
			f.Severity = SevInfo
		}
	}
}

func computeVerdict(findings []Finding, containers []ContainerResult) string {
	maxSev := SevInfo
	for i := range findings {
		if findings[i].Severity > maxSev {
			maxSev = findings[i].Severity
		}
	}
	for _, ct := range containers {
		for i := range ct.Findings {
			if ct.Findings[i].Severity > maxSev {
				maxSev = ct.Findings[i].Severity
			}
		}
	}
	switch {
	case maxSev >= SevCritical:
		return "COMPROMISED"
	case maxSev >= SevHigh:
		return "SUSPICIOUS"
	case maxSev >= SevMedium:
		return "REVIEW"
	default:
		return "CLEAN"
	}
}

// ---------------------------------------------------------------------------
// Host triage script — runs as root on the target
// ---------------------------------------------------------------------------

const triageScript = `
echo "===MEMEXEC===" && find /dev/shm /tmp /var/tmp -type f -executable 2>/dev/null
echo "===DELETED===" && ls -al /proc/*/exe 2>/dev/null | grep 'deleted' | while IFS= read -r line; do bin=$(echo "$line" | sed 's/.* -> //; s/ (deleted)//'); upgraded=false; pkg=""; if command -v dpkg >/dev/null 2>&1; then pkg=$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1); [ -n "$pkg" ] && zgrep -qm1 " upgrade $pkg:" /var/log/dpkg.log* 2>/dev/null && upgraded=true; elif command -v rpm >/dev/null 2>&1; then pkg=$(rpm -qf "$bin" 2>/dev/null); [ $? -eq 0 ] && upgraded=true; fi; if $upgraded; then echo "${line} [PKG_UPGRADED=${pkg}]"; else echo "$line"; fi; done
echo "===UID0===" && awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd
echo "===CRON===" && crontab -l -u root 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' | sed "s/^/$u: /"; done; for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && basename "$f" | grep -qvE '^\.placeholder$' && echo "$d/$(basename "$f")"; done; done
echo "===SUID===" && find / -path /var/lib/docker -prune -o -path /var/lib/containers -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | grep -vE '^/(usr/(bin|lib|libexec|sbin)|bin|sbin|proc|sys|snap)/'
echo "===SGIDDIR===" && find / -path /var/lib/docker -prune -o -path /var/lib/containers -prune -o -type d -perm -2000 -print 2>/dev/null | grep -vE '^/(usr/(bin|lib|libexec|sbin)|bin|sbin|proc|sys|snap)/'
echo "===SERVICES===" && systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}'
echo "===LISTEN===" && ss -tlnp 2>/dev/null | tail -n +2
echo "===KMOD===" && lsmod 2>/dev/null | tail -n +2 | awk '{print $1}'
echo "===AUTHKEYS===" && for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && keys=$(wc -l < "$f" | tr -d ' ') && mod=$(stat -c %Y "$f") && now=$(date +%s) && age=$(( (now - mod) / 86400 )) && echo "$f: keys=$keys age_days=$age" && cat "$f"; done 2>/dev/null
echo "===HIDDEN===" && find /tmp /dev/shm /var/tmp -name '.*' -type f 2>/dev/null
echo "===NETNS===" && ls /var/run/netns/ 2>/dev/null; ip netns list 2>/dev/null
echo "===CONTAINERENV===" && cat /proc/1/cgroup 2>/dev/null | head -5; [ -f /.dockerenv ] && echo "dockerenv=true"; [ -f /run/.containerenv ] && echo "containerenv=true"
echo "===TIMERS===" && systemctl list-timers --no-pager --no-legend 2>/dev/null
echo "===SHELLINIT===" && for u in /root /home/*; do for rc in .bashrc .bash_profile .profile; do [ -f "$u/$rc" ] && grep -nE '(curl |wget |nc |ncat |python|perl -e|ruby -e|base64|eval |exec )' "$u/$rc" 2>/dev/null | sed "s|^|$u/$rc:|"; done; done; find /etc/profile.d/ -type f -newer /etc/passwd 2>/dev/null
echo "===LDPRELOAD===" && cat /etc/ld.so.preload 2>/dev/null
echo "===RCLOCAL===" && cat /etc/rc.local 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^exit 0'; for f in /etc/init.d/*; do [ -f "$f" ] || continue; base=$(basename "$f"); case "$base" in README|skeleton|rc|rcS|single|*.dpkg*) continue ;; esac; if command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && echo "$f [PKG_OWNED]" || echo "$f"; elif command -v rpm >/dev/null 2>&1; then rpm -qf "$f" >/dev/null 2>&1 && echo "$f [PKG_OWNED]" || echo "$f"; else echo "$f"; fi; done
echo "===PAM===" && pam_check() { for f in "$@"; do if command -v rpm >/dev/null 2>&1; then rpm -qf "$f" >/dev/null 2>&1 && echo "$f [PKG_OWNED]" || echo "$f"; elif command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && echo "$f [PKG_OWNED]" || echo "$f"; else echo "$f"; fi; done; }; pam_check $(find /etc/pam.d/ -type f -newer /etc/passwd 2>/dev/null) $(find /lib/security/ /lib64/security/ /usr/lib/security/ /usr/lib64/security/ -name '*.so' -newer /etc/passwd -type f 2>/dev/null)
echo "===ATJOBS===" && atq 2>/dev/null
echo "===PROCHIDE===" && ps_count=$(ps aux 2>/dev/null | tail -n +2 | wc -l); proc_count=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l); echo "ps=$ps_count proc=$proc_count diff=$((proc_count - ps_count))"
echo "===MODBINS===" && find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -50 | while IFS= read -r bin; do upgraded=false; if command -v dpkg >/dev/null 2>&1; then pkg=$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1); [ -n "$pkg" ] && zgrep -qm1 " upgrade $pkg:" /var/log/dpkg.log* 2>/dev/null && upgraded=true; elif command -v rpm >/dev/null 2>&1; then pkg=$(rpm -qf "$bin" 2>/dev/null); [ $? -eq 0 ] && upgraded=true; fi; if $upgraded; then echo "${bin} [PKG_UPGRADED=${pkg}]"; else echo "$bin"; fi; done
echo "===IMMUTABLE===" && lsattr -R /etc /tmp /var/tmp /dev/shm 2>/dev/null | grep -- '----i'
echo "===TAINTED===" && tval=$(cat /proc/sys/kernel/tainted 2>/dev/null); if [ "$tval" != "0" ] && [ -n "$tval" ]; then oot=""; for tf in /sys/module/*/taint; do [ -r "$tf" ] && tv=$(cat "$tf" 2>/dev/null | tr -d '[:space:]') && [ -n "$tv" ] && mod=$(basename "$(dirname "$tf")") && oot="$oot $mod"; done; oot=$(echo "$oot" | xargs); known=true; if [ -n "$oot" ]; then for m in $oot; do case "$m" in nvidia*|nv_*|vmw_*|vmmon|vmnet|vboxdrv|vboxnetflt|vboxnetadp|vboxpci|wireguard|zfs|spl) ;; *) known=false; break ;; esac; done; fi; if $known && [ -n "$oot" ]; then echo "${tval} [KNOWN_DRIVERS=${oot// /,}]"; else echo "$tval"; fi; else echo "$tval"; fi
echo "===HISTORY===" && appliance=false; { [ -d /usr/share/truenas ] || [ -f /etc/pve/.version ] || [ -f /etc/opnsense_version ] || [ -d /cf/conf ] || [ -d /etc/unifi ] || [ -f /etc/synoinfo.conf ] || [ -f /etc/config/uLinux.conf ]; } && appliance=true; for u in /root /home/*; do [ -d "$u" ] && hist="$u/.bash_history" && if [ -L "$hist" ]; then echo "$u: SYMLINKED -> $(readlink -f "$hist")"; elif [ ! -f "$hist" ]; then $appliance && echo "$u: MISSING [APPLIANCE_OS]" || echo "$u: MISSING"; elif [ ! -s "$hist" ]; then $appliance && echo "$u: EMPTY [APPLIANCE_OS]" || echo "$u: EMPTY"; fi; done
echo "===KNOWNHOSTS===" && for f in /root/.ssh/known_hosts /home/*/.ssh/known_hosts; do [ -f "$f" ] && echo "$f: $(wc -l < "$f") hosts"; done 2>/dev/null
echo "===SHADOWPERMS===" && ls -la /etc/shadow 2>/dev/null
echo "===OUTBOUND===" && ss -tnp 2>/dev/null | grep ESTAB
echo "===DNSCONF===" && cat /etc/resolv.conf 2>/dev/null | grep -v '^#' | grep -v '^$'
echo "===IPTABLES===" && iptables -L -n --line-numbers 2>/dev/null | grep -vE '^Chain|^num|^$|policy ACCEPT' | head -30
echo "===FAILEDAUTH===" && count=0; lines=0; if command -v journalctl >/dev/null 2>&1; then lines=$(journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -ciE 'fail|invalid|refused'); fi; fcount=$(grep -ciE 'fail|invalid|refused' /var/log/auth.log 2>/dev/null || echo 0); count=$((lines + fcount)); echo "TOTAL_FAILURES=$count"; journalctl -u sshd --since "24 hours ago" --no-pager 2>/dev/null | grep -iE 'fail|invalid|refused' | tail -20; grep -iE 'fail|invalid|refused' /var/log/auth.log 2>/dev/null | tail -20
echo "===LOGCHECK===" && find /var/log -maxdepth 1 -type f -empty ! -name '*.1' ! -name '*.gz' ! -name '*.old' ! -name '*.xz' ! -name 'faillog' ! -name 'btmp' ! -name 'lastlog' 2>/dev/null | grep -vE '\-[0-9]{8}$'
echo "===PKGVERIFY===" && if command -v dpkg >/dev/null 2>&1; then dpkg -V 2>/dev/null | grep -vE '^..5' | head -50; dpkg -V 2>/dev/null | grep -E '^..5' | while IFS= read -r line; do file=$(echo "$line" | awk '{print $NF}'); conffile=false; pkg=$(dpkg -S "$file" 2>/dev/null | head -1 | cut -d: -f1); [ -n "$pkg" ] && dpkg-query -s "$pkg" 2>/dev/null | grep -q "^Conffiles:" && dpkg-query -s "$pkg" 2>/dev/null | sed -n '/^Conffiles:/,/^[^ ]/p' | grep -q " $file " && conffile=true; $conffile && echo "${line} [CONFFILE]" || echo "${line} [HASH_MISMATCH]"; done; elif command -v rpm >/dev/null 2>&1; then rpm -Va --nomtime --noconfig 2>/dev/null | grep -E '^..5' | while IFS= read -r line; do file=$(echo "$line" | awk '{print $NF}'); echo "${line} [HASH_MISMATCH]"; done | head -50; elif command -v apk >/dev/null 2>&1; then apk verify 2>&1 | grep -i 'checksum' | head -50; fi
echo "===PROCTREE===" && for pid in /proc/[0-9]*/exe; do p=${pid%/exe}; p=${p#/proc/}; [ -r "/proc/$p/status" ] || continue; exe=$(readlink "/proc/$p/exe" 2>/dev/null | sed 's/ (deleted)//') || continue; [ -z "$exe" ] && continue; ppid=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null); pexe=$(readlink "/proc/$ppid/exe" 2>/dev/null | sed 's/ (deleted)//' 2>/dev/null); cmdline=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null); uid=$(awk '/^Uid:/{print $2}' "/proc/$p/status" 2>/dev/null); echo "pid=$p ppid=$ppid uid=$uid exe=$exe pexe=$pexe cmd=$cmdline"; done 2>/dev/null
echo "===PROCMASQ===" && for pid in /proc/[0-9]*/exe; do p=${pid%/exe}; p=${p#/proc/}; exe=$(readlink "/proc/$p/exe" 2>/dev/null | sed 's/ (deleted)//') || continue; [ -z "$exe" ] && continue; cmdline=$(cat "/proc/$p/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 500); [ -z "$cmdline" ] && continue; cmd0=$(echo "$cmdline" | awk '{print $1}'); exebase=$(basename "$exe"); cmd0base=$(basename "$cmd0" 2>/dev/null); if [ "$cmd0base" != "$exebase" ]; then case "$cmd0" in \[*\]) ;; -bash|-sh|-zsh|-dash) ;; *) echo "pid=$p exe=$exe cmdline=$cmdline"; ;; esac; fi; done 2>/dev/null
echo "===ORPHANBIN===" && { for dir in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do [ -d "$dir" ] && find "$dir" -maxdepth 1 -type f 2>/dev/null; done; } | while IFS= read -r f; do if command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && continue; elif command -v rpm >/dev/null 2>&1; then rpm -qf "$f" >/dev/null 2>&1 && continue; fi; ls -la "$f" 2>/dev/null; done | head -80
echo "===PROCMEM===" && for pid in /proc/[0-9]*/maps; do p=${pid%/maps}; p=${p#/proc/}; [ -r "/proc/$p/maps" ] || continue; anon=$(grep -c 'rwxp.*00000000 00:00 0' "/proc/$p/maps" 2>/dev/null); [ "$anon" -gt 0 ] 2>/dev/null && exe=$(readlink "/proc/$p/exe" 2>/dev/null | sed 's/ (deleted)//'); echo "pid=$p exe=$exe anon_rwx=$anon"; done 2>/dev/null | awk -F'anon_rwx=' '$2 > 0 {print}'
echo "===PROCENV===" && for pid in /proc/[0-9]*/environ; do p=${pid%/environ}; p=${p#/proc/}; [ -r "/proc/$p/environ" ] || continue; env=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null); preload=$(echo "$env" | grep '^LD_PRELOAD=' 2>/dev/null); [ -n "$preload" ] && exe=$(readlink "/proc/$p/exe" 2>/dev/null) && echo "pid=$p exe=$exe $preload"; done 2>/dev/null
echo "===LOGGAP===" && for log in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do [ -f "$log" ] || continue; lines=$(wc -l < "$log"); [ "$lines" -lt 10 ] && continue; first_ts=$(head -1 "$log" | awk '{print $1,$2,$3}'); last_ts=$(tail -1 "$log" | awk '{print $1,$2,$3}'); first_e=$(date -d "$first_ts" +%s 2>/dev/null); last_e=$(date -d "$last_ts" +%s 2>/dev/null); [ -z "$first_e" ] || [ -z "$last_e" ] && continue; span=$((last_e - first_e)); expected_rate=$((lines * 86400 / (span + 1))); [ "$expected_rate" -gt 0 ] && echo "$log: lines=$lines span_hours=$((span/3600)) rate=${expected_rate}/day"; awk 'NR<=200 || NR>(LINES-200){print}' LINES="$lines" "$log" 2>/dev/null | while IFS= read -r line; do ts=$(echo "$line" | awk '{print $1,$2,$3}'); epoch=$(date -d "$ts" +%s 2>/dev/null) || continue; [ -z "$epoch" ] && continue; if [ -n "$prev_epoch" ]; then gap=$((epoch - prev_epoch)); [ "$gap" -gt 3600 ] && echo "$log: gap=${gap}s (~$((gap/3600))h) after=$prev_ts"; fi; prev_epoch=$epoch; prev_ts="$ts"; done; done 2>/dev/null | head -30
echo "===ORPHANSVC===" && systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null | awk '{print $1}' | while IFS= read -r svc; do path=$(systemctl show -p FragmentPath "$svc" 2>/dev/null | cut -d= -f2-); [ -z "$path" ] || [ ! -f "$path" ] && continue; owned=false; if command -v dpkg >/dev/null 2>&1; then dpkg -S "$path" >/dev/null 2>&1 && owned=true; elif command -v rpm >/dev/null 2>&1; then rpm -qf "$path" >/dev/null 2>&1 && owned=true; fi; $owned || echo "$svc path=$path"; done 2>/dev/null | head -30
echo "===USERACCT===" && while IFS=: read -r user _ uid gid _ home shell; do [ "$uid" -ge 1000 ] 2>/dev/null || [ "$uid" = "0" ] || continue; [ "$shell" = "/usr/sbin/nologin" ] || [ "$shell" = "/bin/false" ] || [ "$shell" = "/sbin/nologin" ] && continue; lastlog_line=$(lastlog -u "$user" 2>/dev/null | tail -1); never_logged=$(echo "$lastlog_line" | grep -c 'Never logged in'); has_home=false; [ -d "$home" ] && has_home=true; sudoer=false; grep -rq "^$user " /etc/sudoers /etc/sudoers.d/ 2>/dev/null && sudoer=true; echo "user=$user uid=$uid home_exists=$has_home never_logged=$never_logged sudoer=$sudoer shell=$shell"; done < /etc/passwd 2>/dev/null; echo "---SUDOERS_D---"; for f in /etc/sudoers.d/*; do [ -f "$f" ] || continue; owned=false; if command -v dpkg >/dev/null 2>&1; then dpkg -S "$f" >/dev/null 2>&1 && owned=true; elif command -v rpm >/dev/null 2>&1; then rpm -qf "$f" >/dev/null 2>&1 && owned=true; fi; $owned || echo "$f [UNPACKAGED]"; done 2>/dev/null
echo "===DNSLEAK===" && configured_dns=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u); ss -unp 2>/dev/null | grep ':53 ' | while IFS= read -r line; do remote=$(echo "$line" | awk '{print $5}' | sed 's/:53$//'); match=false; for dns in $configured_dns; do [ "$remote" = "$dns" ] && match=true && break; done; $match || echo "$line [NON_CONFIGURED_DNS=$remote]"; done 2>/dev/null
echo "===LISTENORPHAN===" && ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do prog=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+'); pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+'); [ -z "$pid" ] && continue; exe=$(readlink "/proc/$pid/exe" 2>/dev/null | sed 's/ (deleted)//'); [ -z "$exe" ] && continue; owned=false; if command -v dpkg >/dev/null 2>&1; then dpkg -S "$exe" >/dev/null 2>&1 && owned=true; elif command -v rpm >/dev/null 2>&1; then rpm -qf "$exe" >/dev/null 2>&1 && owned=true; fi; $owned || echo "port=$(echo "$line" | awk '{print $4}') exe=$exe pid=$pid prog=$prog"; done 2>/dev/null
echo "===DONE==="
`

// ---------------------------------------------------------------------------
// Container triage — lightweight, works in minimal images (sh, not bash)
// ---------------------------------------------------------------------------

const containerTriageScript = `
echo "===CT_PROCS==="
if command -v ps >/dev/null 2>&1; then ps aux 2>/dev/null; else for p in /proc/[0-9]*; do [ -r "$p/cmdline" ] && printf "%s: %s\n" "$(basename $p)" "$(tr '\0' ' ' < $p/cmdline)"; done; fi
echo "===CT_NET==="
if command -v ss >/dev/null 2>&1; then ss -tlnp 2>/dev/null; elif command -v netstat >/dev/null 2>&1; then netstat -tlnp 2>/dev/null; elif [ -r /proc/net/tcp ]; then cat /proc/net/tcp 2>/dev/null; fi
echo "===CT_EXEC==="
if command -v find >/dev/null 2>&1; then find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null; fi
echo "===CT_HIDDEN==="
if command -v find >/dev/null 2>&1; then find /tmp /dev/shm /var/tmp -name '.*' -type f 2>/dev/null; fi
echo "===CT_USERS==="
[ -r /etc/passwd ] && awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null
echo "===CT_CRON==="
if command -v crontab >/dev/null 2>&1; then crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^[[:space:]]*$'; fi
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly; do [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && echo "$d/$(basename "$f")"; done 2>/dev/null; done
echo "===CT_DOCKERSOCK==="
[ -S /var/run/docker.sock ] && echo "/var/run/docker.sock EXISTS"
ls -la /var/run/docker.sock 2>/dev/null
echo "===CT_K8S==="
[ -d /var/run/secrets/kubernetes.io ] && find /var/run/secrets/kubernetes.io -type f 2>/dev/null
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo "SERVICE_ACCOUNT_TOKEN_PRESENT"
echo "===CT_DONE==="
`

// ---------------------------------------------------------------------------
// Section maps
// ---------------------------------------------------------------------------

var sectionMarkers = map[string]string{
	"===MEMEXEC===":      "MEMEXEC",
	"===DELETED===":      "DELETED",
	"===UID0===":         "UID0",
	"===CRON===":         "CRON",
	"===SUID===":         "SUID",
	"===SGIDDIR===":      "SGIDDIR",
	"===SERVICES===":     "SERVICES",
	"===LISTEN===":       "LISTEN",
	"===KMOD===":         "KMOD",
	"===AUTHKEYS===":     "AUTHKEYS",
	"===HIDDEN===":       "HIDDEN",
	"===NETNS===":        "NETNS",
	"===CONTAINERENV===": "CONTAINERENV",
	"===TIMERS===":       "TIMERS",
	"===SHELLINIT===":    "SHELLINIT",
	"===LDPRELOAD===":    "LDPRELOAD",
	"===RCLOCAL===":      "RCLOCAL",
	"===PAM===":          "PAM",
	"===ATJOBS===":       "ATJOBS",
	"===PROCHIDE===":     "PROCHIDE",
	"===MODBINS===":      "MODBINS",
	"===IMMUTABLE===":    "IMMUTABLE",
	"===TAINTED===":      "TAINTED",
	"===HISTORY===":      "HISTORY",
	"===KNOWNHOSTS===":   "KNOWNHOSTS",
	"===SHADOWPERMS===":  "SHADOWPERMS",
	"===OUTBOUND===":     "OUTBOUND",
	"===DNSCONF===":      "DNSCONF",
	"===IPTABLES===":     "IPTABLES",
	"===FAILEDAUTH===":   "FAILEDAUTH",
	"===LOGCHECK===":     "LOGCHECK",
	"===PKGVERIFY===":    "PKGVERIFY",
	"===PROCTREE===":     "PROCTREE",
	"===PROCMASQ===":     "PROCMASQ",
	"===ORPHANBIN===":    "ORPHANBIN",
	"===PROCMEM===":      "PROCMEM",
	"===PROCENV===":      "PROCENV",
	"===LOGGAP===":       "LOGGAP",
	"===ORPHANSVC===":    "ORPHANSVC",
	"===USERACCT===":     "USERACCT",
	"===DNSLEAK===":      "DNSLEAK",
	"===LISTENORPHAN===": "LISTENORPHAN",
	"===DONE===":         "",
}

var ctSectionMarkers = map[string]string{
	"===CT_PROCS===":      "PROCS",
	"===CT_NET===":        "NET",
	"===CT_EXEC===":       "EXEC",
	"===CT_HIDDEN===":     "HIDDEN",
	"===CT_USERS===":      "USERS",
	"===CT_CRON===":       "CRON",
	"===CT_DOCKERSOCK===": "DOCKERSOCK",
	"===CT_K8S===":        "K8S",
	"===CT_DONE===":       "",
}

// ---------------------------------------------------------------------------
// SSH helpers
// ---------------------------------------------------------------------------

func buildAuthMethods(password, keyPath string) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	if keyPath != "" {
		expanded := keyPath
		if strings.HasPrefix(expanded, "~/") {
			home, _ := os.UserHomeDir()
			expanded = filepath.Join(home, expanded[2:])
		}
		keyData, err := os.ReadFile(expanded)
		if err == nil {
			var signer ssh.Signer
			if password != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(password))
			} else {
				signer, err = ssh.ParsePrivateKey(keyData)
			}
			if err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
			} else {
				log.Warn("Failed to parse SSH key", "path", keyPath, "err", err)
			}
		} else {
			log.Warn("Failed to read SSH key", "path", keyPath, "err", err)
		}
	}

	if password != "" {
		methods = append(methods, ssh.Password(password))
	}

	return methods
}

func runCmd(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = io.Discard
	err = session.Run(cmd)
	return strings.TrimSpace(out.String()), err
}

func runCmdWithStdin(client *ssh.Client, cmd, stdinData string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("session: %w", err)
	}
	defer session.Close()

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	go func() {
		defer stdinPipe.Close()
		io.WriteString(stdinPipe, stdinData)
	}()

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = io.Discard
	err = session.Run(cmd)
	return out.String(), err
}

func runAsRoot(client *ssh.Client, cmd, sudoPassword string, isRoot bool) (string, error) {
	if isRoot {
		return runCmd(client, cmd)
	}
	out, err := runCmd(client, "sudo -n "+cmd)
	if err == nil {
		return out, nil
	}
	if sudoPassword == "" {
		return out, fmt.Errorf("sudo requires password but none provided")
	}
	return runCmdWithStdin(client, fmt.Sprintf("sudo -S -p '' %s", cmd), sudoPassword+"\n")
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

func parseFindings(raw string, markers map[string]string) []Finding {
	var findings []Finding
	section := ""

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)

		if newSection, ok := markers[line]; ok {
			section = newSection
			continue
		}

		if line == "" || section == "" {
			continue
		}

		sev := SevInfo
		if s, ok := defaultSeverity[section]; ok {
			sev = s
		}

		f := Finding{
			Check:    section,
			Detail:   line,
			Severity: sev,
		}
		analyzeFinding(&f)
		findings = append(findings, f)
	}

	return findings
}

// ---------------------------------------------------------------------------
// Container introspection
// ---------------------------------------------------------------------------

type containerInfo struct {
	ID    string
	Name  string
	Image string
}

func parseContainerList(raw string) []containerInfo {
	var containers []containerInfo
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		containers = append(containers, containerInfo{
			ID:    parts[0],
			Name:  strings.TrimPrefix(parts[1], "/"),
			Image: parts[2],
		})
	}
	return containers
}

func triageContainers(client *ssh.Client, sudoPassword string, isRoot bool, ip string) []ContainerResult {
	runtime := "docker"
	if _, err := runAsRoot(client, "command -v docker", sudoPassword, isRoot); err != nil {
		if _, err := runAsRoot(client, "command -v podman", sudoPassword, isRoot); err != nil {
			log.Info("No container runtime found", "host", ip)
			return nil
		}
		runtime = "podman"
	}

	log.Info("Container runtime detected", "host", ip, "runtime", runtime)

	listCmd := fmt.Sprintf(`%s ps --format '{{.ID}}|{{.Names}}|{{.Image}}' --no-trunc`, runtime)
	listOut, err := runAsRoot(client, listCmd, sudoPassword, isRoot)
	if err != nil || strings.TrimSpace(listOut) == "" {
		log.Info("No running containers", "host", ip)
		return nil
	}

	containers := parseContainerList(listOut)
	log.Info("Enumerating containers", "host", ip, "count", len(containers))

	var results []ContainerResult

	for _, ct := range containers {
		cr := ContainerResult{
			ID:    ct.ID[:12],
			Name:  ct.Name,
			Image: ct.Image,
		}

		log.Info("Inspecting container", "host", ip, "container", ct.Name)

		// --- Host-side inspection via docker inspect ---
		inspectCmd := fmt.Sprintf(
			`%s inspect --format '`+
				`PRIV={{.HostConfig.Privileged}}`+
				`||CAPADD={{.HostConfig.CapAdd}}`+
				`||NETMODE={{.HostConfig.NetworkMode}}`+
				`||PIDMODE={{.HostConfig.PidMode}}`+
				`||DEVICES={{range .HostConfig.Devices}}{{.PathOnHost}},{{end}}`+
				`' %s`,
			runtime, ct.ID,
		)
		inspectOut, _ := runAsRoot(client, inspectCmd, sudoPassword, isRoot)
		inspectOut = strings.TrimSpace(inspectOut)

		// Detect VPN containers: known image + /dev/net/tun device
		vpnImages := []string{"gluetun", "wireguard", "openvpn", "tailscale", "netbird", "nordvpn", "surfshark", "pia-"}
		isVPN := false
		hasTun := false
		imageLower := strings.ToLower(ct.Image)
		for _, vpn := range vpnImages {
			if strings.Contains(imageLower, vpn) {
				isVPN = true
				break
			}
		}
		for _, field := range strings.Split(inspectOut, "||") {
			if strings.HasPrefix(field, "DEVICES=") && strings.Contains(field, "/dev/net/tun") {
				hasTun = true
			}
		}

		if strings.Contains(inspectOut, "PRIV=true") {
			cr.Findings = append(cr.Findings, Finding{
				Check: "CONFIG", Detail: "container is PRIVILEGED — full host access", Severity: SevCritical,
			})
		}

		for _, field := range strings.Split(inspectOut, "||") {
			if strings.HasPrefix(field, "CAPADD=") {
				caps := strings.TrimPrefix(field, "CAPADD=")
				caps = strings.Trim(caps, "[]")
				if caps != "" {
					for _, cap := range strings.Fields(caps) {
						cap = strings.TrimSpace(cap)
						if dangerousCaps[cap] {
							sev := SevHigh
							detail := "dangerous capability: " + cap
							// VPN containers need NET_ADMIN + tun for tunnel creation
							if cap == "NET_ADMIN" && isVPN && hasTun {
								sev = SevInfo
								detail = "NET_ADMIN capability (expected — VPN tunnel creation)"
							}
							cr.Findings = append(cr.Findings, Finding{
								Check: "CONFIG", Detail: detail, Severity: sev,
							})
						}
					}
				}
			}
			if strings.HasPrefix(field, "NETMODE=host") {
				cr.Findings = append(cr.Findings, Finding{
					Check: "CONFIG", Detail: "uses host network namespace", Severity: SevHigh,
				})
			}
			if strings.HasPrefix(field, "PIDMODE=host") {
				cr.Findings = append(cr.Findings, Finding{
					Check: "CONFIG", Detail: "uses host PID namespace", Severity: SevHigh,
				})
			}
		}

		// Bind mounts
		mountCmd := fmt.Sprintf(
			`%s inspect --format '{{range .Mounts}}{{.Type}}|{{.Source}}|{{.Destination}}|{{.RW}};{{end}}' %s`,
			runtime, ct.ID,
		)
		mountOut, _ := runAsRoot(client, mountCmd, sudoPassword, isRoot)
		for _, m := range strings.Split(strings.TrimSpace(mountOut), ";") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			parts := strings.SplitN(m, "|", 4)
			if len(parts) < 4 {
				continue
			}
			src, dst, rw := parts[1], parts[2], parts[3]
			sev := SevInfo
			detail := fmt.Sprintf("%s -> %s (rw=%s)", src, dst, rw)

			// Flag sensitive mounts
			if src == "/var/run/docker.sock" || dst == "/var/run/docker.sock" {
				sev = SevCritical
				detail += " — DOCKER SOCKET: full host escape"

				nameLower := strings.ToLower(ct.Name)
				imageLower := strings.ToLower(ct.Image)
				for _, allowed := range dockerSockAllowlist {
					if strings.Contains(nameLower, allowed) || strings.Contains(imageLower, allowed) {
						sev = SevMedium
						detail += fmt.Sprintf(" (allowlisted: %s)", allowed)
						break
					}
				}
			} else if src == "/" {
				sev = SevCritical
				detail += " — HOST ROOT FILESYSTEM"
			} else {
				// Safe read-only single-file mounts
				safeRO := false
				if rw == "false" {
					for _, safe := range []string{"/etc/localtime", "/etc/timezone", "/etc/resolv.conf", "/etc/hostname", "/etc/hosts"} {
						if src == safe {
							safeRO = true
							break
						}
					}
				}
				if !safeRO {
					for _, sensitive := range []string{"/etc", "/root", "/home", "/var/run"} {
						if src == sensitive || strings.HasPrefix(src, sensitive+"/") {
							sev = SevHigh
							detail += " — sensitive host path"
							break
						}
					}
				}
			}

			cr.Findings = append(cr.Findings, Finding{
				Check: "MOUNT", Detail: detail, Severity: sev,
			})
		}

		// --- In-container triage via docker exec ---
		escapedScript := strings.ReplaceAll(containerTriageScript, "'", `'\''`)
		execCmd := fmt.Sprintf(`%s exec %s sh -c '%s'`, runtime, ct.ID, escapedScript)
		execOut, err := runAsRoot(client, execCmd, sudoPassword, isRoot)
		if err != nil {
			cr.Findings = append(cr.Findings, Finding{
				Check: "INFO", Detail: "in-container triage failed (minimal image?): " + err.Error(), Severity: SevInfo,
			})

			// Fallback: docker top from host side
			topCmd := fmt.Sprintf(`%s top %s -eo pid,user,comm,args`, runtime, ct.ID)
			topOut, topErr := runAsRoot(client, topCmd, sudoPassword, isRoot)
			if topErr == nil {
				for _, line := range strings.Split(topOut, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "PID") {
						cr.Findings = append(cr.Findings, Finding{
							Check: "PROCS", Detail: line, Severity: SevInfo,
						})
					}
				}
			}
		} else {
			parsed := parseFindings(execOut, ctSectionMarkers)

			// POST-PROCESS for CT_DOCKERSOCK allowlist
			nameLower := strings.ToLower(ct.Name)
			imageLower := strings.ToLower(ct.Image)
			for i := range parsed {
				if parsed[i].Check == "DOCKERSOCK" && parsed[i].Severity == SevCritical {
					for _, allowed := range dockerSockAllowlist {
						if strings.Contains(nameLower, allowed) || strings.Contains(imageLower, allowed) {
							parsed[i].Severity = SevMedium
							parsed[i].Detail += fmt.Sprintf(" (allowlisted: %s)", allowed)
							break
						}
					}
				}
			}

			cr.Findings = append(cr.Findings, parsed...)
		}

		results = append(results, cr)
	}

	return results
}

// ---------------------------------------------------------------------------
// Host triage orchestrator
// ---------------------------------------------------------------------------

func triageHost(ip, port, username, sshPassword, sudoPassword, keyPath string) (result HostResult) {
	start := time.Now()
	result = HostResult{IP: ip}
	defer func() { result.Duration = time.Since(start).Round(time.Millisecond).String() }()

	authMethods := buildAuthMethods(sshPassword, keyPath)
	if len(authMethods) == 0 {
		result.Status = "NO_AUTH"
		result.Error = "no valid authentication methods"
		result.Verdict = "ERROR"
		return result
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	log.Info("Dialing", "host", ip, "user", username)
	client, err := ssh.Dial("tcp", ip+":"+port, config)
	if err != nil {
		result.Status = "UNREACHABLE"
		result.Error = err.Error()
		result.Verdict = "ERROR"
		return result
	}
	defer client.Close()

	// Step 1: check current uid
	uidOut, err := runCmd(client, "id -u")
	if err != nil {
		result.Status = "UID_CHECK_ERR"
		result.Error = fmt.Sprintf("failed to check uid: %v", err)
		result.Verdict = "ERROR"
		return result
	}

	isRoot := uidOut == "0"
	if isRoot {
		log.Info("Already root", "host", ip)
		result.RootMethod = "direct"
	} else {
		log.Info("Non-root login", "host", ip, "uid", uidOut, "escalating", "sudo")
		result.RootMethod = "sudo"
	}

	// Step 2: run host triage payload
	escapedScript := strings.ReplaceAll(triageScript, "'", `'\''`)
	raw, err := runAsRoot(client, fmt.Sprintf("bash -c '%s'", escapedScript), sudoPassword, isRoot)

	if err != nil && !strings.Contains(raw, "===DONE===") {
		if strings.Contains(raw, "Sorry, try again") || strings.Contains(raw, "incorrect password") {
			result.Status = "SUDO_DENIED"
			result.Error = "sudo authentication failed — wrong password"
			result.Verdict = "ERROR"
			return result
		}
		result.Status = "EXEC_ERR"
		result.Error = err.Error()
		result.Verdict = "ERROR"
		return result
	}

	result.Status = "OK"
	result.Findings = parseFindings(raw, sectionMarkers)

	// Step 3: container introspection
	result.Containers = triageContainers(client, sudoPassword, isRoot, ip)

	// Step 4: compute verdict
	result.Verdict = computeVerdict(result.Findings, result.Containers)

	return result
}

// ---------------------------------------------------------------------------
// JSON report
// ---------------------------------------------------------------------------

type Report struct {
	Timestamp string       `json:"timestamp"`
	Results   []HostResult `json:"results"`
}

func writeJSON(results []HostResult) {
	report := Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   results,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error("Failed to marshal JSON", "err", err)
		return
	}

	filename := fmt.Sprintf("triage_%s.json", time.Now().Format("20060102_150405"))
	if err := os.WriteFile(filename, data, 0600); err != nil {
		log.Error("Failed to write report", "err", err)
		return
	}

	log.Info("Report saved", "file", filename)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func severityCounts(findings []Finding) (crit, high, med, low, info int) {
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			crit++
		case SevHigh:
			high++
		case SevMedium:
			med++
		case SevLow:
			low++
		default:
			info++
		}
	}
	return
}

func allFindings(r HostResult) []Finding {
	all := make([]Finding, 0, len(r.Findings))
	all = append(all, r.Findings...)
	for _, ct := range r.Containers {
		all = append(all, ct.Findings...)
	}
	return all
}

func renderTable(results []HostResult) string {
	critStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196")) // bright red
	highStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))              // red
	medStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))              // yellow
	lowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))              // blue
	infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))              // dim
	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))               // green
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212")).Padding(0, 1)
	borderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("62"))

	// Summary table
	rows := [][]string{}
	for _, r := range results {
		all := allFindings(r)
		c, h, m, l, i := severityCounts(all)
		findingStr := fmt.Sprintf("%dC %dH %dM %dL %dI", c, h, m, l, i)
		if r.Error != "" {
			findingStr = r.Error
		}
		ctCount := fmt.Sprintf("%d", len(r.Containers))
		rows = append(rows, []string{r.IP, r.Status, r.Verdict, r.RootMethod, ctCount, r.Duration, findingStr})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(borderStyle).
		Headers("HOST", "STATUS", "VERDICT", "PRIV", "CT", "TIME", "FINDINGS (C/H/M/L/I)").
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return headerStyle
			}
			s := lipgloss.NewStyle().Padding(0, 1)
			if col == 2 && row >= 0 && row < len(results) {
				switch results[row].Verdict {
				case "COMPROMISED":
					return s.Bold(true).Foreground(lipgloss.Color("196"))
				case "SUSPICIOUS":
					return s.Foreground(lipgloss.Color("9"))
				case "REVIEW":
					return s.Foreground(lipgloss.Color("11"))
				case "CLEAN":
					return s.Foreground(lipgloss.Color("10"))
				default:
					return s.Foreground(lipgloss.Color("8"))
				}
			}
			return s
		}).
		Rows(rows...)

	// Detail view — only show MEDIUM+ findings in terminal
	var details strings.Builder

	for _, r := range results {
		if r.Status != "OK" {
			continue
		}

		all := allFindings(r)
		c, h, m, _, i := severityCounts(all)
		if c+h+m == 0 {
			continue
		}

		verdictStyle := okStyle
		switch r.Verdict {
		case "COMPROMISED":
			verdictStyle = critStyle
		case "SUSPICIOUS":
			verdictStyle = highStyle
		case "REVIEW":
			verdictStyle = medStyle
		}

		details.WriteString(verdictStyle.Bold(true).Render(
			fmt.Sprintf("\n=== %s [%s] ===", r.IP, r.Verdict)) + "\n")

		// Host findings grouped by severity
		renderFindingsByGroup(&details, "Host", r.Findings, critStyle, highStyle, medStyle, lowStyle)

		// Container findings
		for _, ct := range r.Containers {
			ctC, ctH, ctM, _, _ := severityCounts(ct.Findings)
			if ctC+ctH+ctM == 0 {
				continue
			}
			label := fmt.Sprintf("  Container: %s (%s) [%s]", ct.Name, ct.Image, ct.ID)
			details.WriteString(headerStyle.Render(label) + "\n")
			renderFindingsByGroup(&details, "    ", ct.Findings, critStyle, highStyle, medStyle, lowStyle)
		}

		if i > 0 {
			details.WriteString(infoStyle.Render(
				fmt.Sprintf("  + %d INFO-level findings (see JSON report)\n", i)))
		}
	}

	return t.String() + details.String()
}

func renderFindingsByGroup(sb *strings.Builder, indent string, findings []Finding, critS, highS, medS, lowS lipgloss.Style) {
	groups := map[Severity][]Finding{}
	for _, f := range findings {
		if f.Severity >= SevMedium {
			groups[f.Severity] = append(groups[f.Severity], f)
		}
	}

	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium} {
		fs, ok := groups[sev]
		if !ok {
			continue
		}

		style := medS
		switch sev {
		case SevCritical:
			style = critS
		case SevHigh:
			style = highS
		}

		sb.WriteString(style.Bold(true).Render(
			fmt.Sprintf("%s  %s:", indent, sev.String())) + "\n")
		for _, f := range fs {
			sb.WriteString(style.Render(
				fmt.Sprintf("%s    [%s] %s", indent, f.Check, f.Detail)) + "\n")
		}
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	var targetStr, username, sshPassword, sudoPassword, keyPath, port string

	authOptions := []huh.Option[string]{
		huh.NewOption("Password", "password"),
		huh.NewOption("SSH Key", "key"),
		huh.NewOption("SSH Key + Password", "both"),
	}
	var authMethod string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Target IPs").
				Description("Comma-separated list of host IPs").
				Value(&targetStr),
			huh.NewInput().
				Title("SSH Port").
				Description("Default: 22").
				Value(&port),
			huh.NewInput().
				Title("SSH Username").
				Description("User to login as (does not need to be root)").
				Value(&username),
			huh.NewSelect[string]().
				Title("SSH Authentication Method").
				Options(authOptions...).
				Value(&authMethod),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("SSH Password").
				Description("Password for SSH login").
				EchoMode(huh.EchoModePassword).
				Value(&sshPassword),
		).WithHideFunc(func() bool {
			return authMethod == "key"
		}),
		huh.NewGroup(
			huh.NewInput().
				Title("SSH Key Path").
				Description("Default: ~/.ssh/id_rsa").
				Value(&keyPath),
		).WithHideFunc(func() bool {
			return authMethod == "password"
		}),
		huh.NewGroup(
			huh.NewInput().
				Title("Sudo Password").
				Description("Leave blank to use SSH password, or if user has NOPASSWD sudo").
				EchoMode(huh.EchoModePassword).
				Value(&sudoPassword),
		),
	)

	if err := form.Run(); err != nil {
		log.Fatal("Form error", "err", err)
	}

	if port == "" {
		port = "22"
	}
	if keyPath == "" && authMethod != "password" {
		keyPath = "~/.ssh/id_rsa"
	}
	if authMethod == "key" {
		sshPassword = ""
	}
	if sudoPassword == "" {
		sudoPassword = sshPassword
	}

	targets := []string{}
	for _, t := range strings.Split(targetStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		log.Fatal("No targets provided")
	}

	log.Info("Starting triage", "hosts", len(targets), "port", port, "user", username)

	results := make([]HostResult, len(targets))
	var wg sync.WaitGroup

	for i, ip := range targets {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			results[idx] = triageHost(host, port, username, sshPassword, sudoPassword, keyPath)
			log.Info("Complete", "host", host, "status", results[idx].Status,
				"verdict", results[idx].Verdict, "containers", len(results[idx].Containers))
		}(i, ip)
	}

	wg.Wait()

	fmt.Println(renderTable(results))
	writeJSON(results)
}
