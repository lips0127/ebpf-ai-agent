// Package filter provides pattern-based filtering to reduce unnecessary AI analysis.
package filter

import (
	"fmt"
	"regexp"
	"strings"
)

// Result represents the filtering decision.
type Result int

const (
	// Whitelisted means the behavior is clearly normal, skip AI analysis.
	Whitelisted Result = iota
	// Blacklisted means the behavior is clearly malicious, alert immediately.
	Blacklisted
	// Greylisted means uncertain, should send to AI for analysis.
	Greylisted
)

func (r Result) String() string {
	switch r {
	case Whitelisted:
		return "whitelisted"
	case Blacklisted:
		return "blacklisted"
	case Greylisted:
		return "greylisted"
	default:
		return "unknown"
	}
}

// Pattern represents a single matching rule.
type Pattern struct {
	Pattern     *regexp.Regexp
	Description string
	Result      Result
}

// Matcher holds all patterns and provides filtering logic.
type Matcher struct {
	whitelist []Pattern
	blacklist []Pattern
	greylist  []Pattern
}

// NewMatcher creates a Matcher with default patterns.
func NewMatcher() *Matcher {
	return &Matcher{
		whitelist: defaultWhitelist(),
		blacklist: defaultBlacklist(),
		greylist:  defaultGreylist(),
	}
}

// Match checks a command/filename against all patterns.
// Returns the most severe match (blacklist > greylist > whitelist).
func (m *Matcher) Match(cmd string, filenames []string) (Result, string) {
	target := strings.TrimSpace(cmd + " " + strings.Join(filenames, " "))

	// Check blacklist first (highest priority for malicious)
	for _, p := range m.blacklist {
		if p.Pattern.MatchString(target) {
			return Blacklisted, p.Description
		}
	}

	// Check greylist (uncertain patterns)
	for _, p := range m.greylist {
		if p.Pattern.MatchString(target) {
			return Greylisted, p.Description
		}
	}

	// Check whitelist (safe patterns)
	for _, p := range m.whitelist {
		if p.Pattern.MatchString(target) {
			return Whitelisted, p.Description
		}
	}

	// Default to greylist if no match
	return Greylisted, "no matching pattern, default to AI analysis"
}

// AddPattern adds a custom pattern to the matcher.
func (m *Matcher) AddPattern(pattern *regexp.Regexp, desc string, result Result) {
	p := Pattern{Pattern: pattern, Description: desc, Result: result}
	switch result {
	case Whitelisted:
		m.whitelist = append(m.whitelist, p)
	case Blacklisted:
		m.blacklist = append(m.blacklist, p)
	case Greylisted:
		m.greylist = append(m.greylist, p)
	}
}

func compilePattern(s string) *regexp.Regexp {
	// Case-insensitive matching for flexibility
	return regexp.MustCompile("(?i)" + s)
}

// defaultWhitelist returns patterns for clearly normal behavior.
func defaultWhitelist() []Pattern {
	return []Pattern{
		{compilePattern(`^ls$`), "list directory contents", Whitelisted},
		{compilePattern(`^ls\s`), "list directory contents with options", Whitelisted},
		{compilePattern(`^pwd$`), "print working directory", Whitelisted},
		{compilePattern(`^cd(\s|$)`), "change directory", Whitelisted},
		{compilePattern(`^echo(\s|$)`), "echo command", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.txt$`), "read text files", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.log$`), "read log files", Whitelisted},
		{compilePattern(`^cat\s+/var/log/`), "read system log files", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.conf$`), "read config files", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.yaml$`), "read yaml files", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.yml$`), "read yaml files", Whitelisted},
		{compilePattern(`^cat\s+[a-zA-Z0-9/\._-]+\.json$`), "read json files", Whitelisted},
		{compilePattern(`^ps$`), "process status", Whitelisted},
		{compilePattern(`^ps\s`), "process status with options", Whitelisted},
		{compilePattern(`^top$`), "top command", Whitelisted},
		{compilePattern(`^htop$`), "htop command", Whitelisted},
		{compilePattern(`^whoami$`), "print current user", Whitelisted},
		{compilePattern(`^id(\s|$)`), "print user identity", Whitelisted},
		{compilePattern(`^date$`), "print date", Whitelisted},
		{compilePattern(`^uptime$`), "system uptime", Whitelisted},
		{compilePattern(`^df\s`), "disk free space", Whitelisted},
		{compilePattern(`^free\s`), "memory usage", Whitelisted},
		{compilePattern(`^uname\s`), "system information", Whitelisted},
		{compilePattern(`^hostname$`), "hostname", Whitelisted},
		{compilePattern(`^tail\s+[a-zA-Z0-9/\._-]+\.log$`), "tail log file", Whitelisted},
		{compilePattern(`^tail\s+-n\s+\d+`), "tail with line count", Whitelisted},
		{compilePattern(`^grep\s`), "grep command", Whitelisted},
		{compilePattern(`^awk\s`), "awk command", Whitelisted},
		{compilePattern(`^sed\s`), "sed command", Whitelisted},
		{compilePattern(`^sort\s`), "sort command", Whitelisted},
		{compilePattern(`^uniq\s`), "uniq command", Whitelisted},
		{compilePattern(`^wc\s`), "word count", Whitelisted},
		{compilePattern(`^head\s`), "head command", Whitelisted},
		{compilePattern(`^less\s`), "less command", Whitelisted},
		{compilePattern(`^mkdir\s+[a-zA-Z0-9/\._-]+$`), "create directory", Whitelisted},
		{compilePattern(`^touch\s+[a-zA-Z0-9/\._-]+$`), "touch file", Whitelisted},
		{compilePattern(`^cp\s+[a-zA-Z0-9/\._-]+\s+[a-zA-Z0-9/\._-]+$`), "copy file", Whitelisted},
		{compilePattern(`^mv\s+[a-zA-Z0-9/\._-]+\s+[a-zA-Z0-9/\._-]+$`), "move file", Whitelisted},
		{compilePattern(`^rm\s+[a-zA-Z0-9/\._-]+$`), "remove file", Whitelisted},
		{compilePattern(`^tar\s+-?[txcfvz]+\s`), "tar archive operations", Whitelisted},
		{compilePattern(`^gzip\s`), "gzip compression", Whitelisted},
		{compilePattern(`^gunzip\s`), "gunzip decompression", Whitelisted},
		{compilePattern(`^zip\s`), "zip compression", Whitelisted},
		{compilePattern(`^unzip\s`), "unzip decompression", Whitelisted},
		{compilePattern(`^ssh\s+[a-zA-Z0-9@\.-]+\s+`+"`"+`.*`+"`"), "ssh with command", Whitelisted},
		{compilePattern(`^scp\s`), "secure copy", Whitelisted},
		{compilePattern(`^rsync\s`), "rsync", Whitelisted},
		{compilePattern(`^curl\s+http`), "http GET request", Whitelisted},
		{compilePattern(`^wget\s+http`), "http download", Whitelisted},
		{compilePattern(`^ping\s`), "ping command", Whitelisted},
		{compilePattern(`^netstat\s`), "network statistics", Whitelisted},
		{compilePattern(`^ss\s`), "socket statistics", Whitelisted},
		{compilePattern(`^ip\s+[a-z]+\s+`), "ip command", Whitelisted},
		{compilePattern(`^ifconfig\s`), "ifconfig command", Whitelisted},
		{compilePattern(`^systemctl\s+[a-z]+\s+[a-zA-Z0-9-]+$`), "systemctl command", Whitelisted},
		{compilePattern(`^journalctl\s`), "journalctl command", Whitelisted},
		{compilePattern(`^docker\s+ps$`), "docker process list", Whitelisted},
		{compilePattern(`^docker\s+images$`), "docker image list", Whitelisted},
		{compilePattern(`^docker\s+logs\s`), "docker logs", Whitelisted},
		{compilePattern(`^git\s+status$`), "git status", Whitelisted},
		{compilePattern(`^git\s+log\s`), "git log", Whitelisted},
		{compilePattern(`^git\s+diff\s`), "git diff", Whitelisted},
		{compilePattern(`^git\s+show\s`), "git show", Whitelisted},
		{compilePattern(`^vim?\s`), "vi/vim editor", Whitelisted},
		{compilePattern(`^nano\s`), "nano editor", Whitelisted},
		{compilePattern(`^make\s`), "make build", Whitelisted},
		{compilePattern(`^gcc\s`), "gcc compiler", Whitelisted},
		{compilePattern(`^g\+\+\s`), "g++ compiler", Whitelisted},
		{compilePattern(`^go\s+build\s`), "go build", Whitelisted},
		{compilePattern(`^pip\s+install\s`), "pip install", Whitelisted},
		{compilePattern(`^npm\s+install\s`), "npm install", Whitelisted},
		{compilePattern(`^apt-get\s+install\s`), "apt-get install", Whitelisted},
		{compilePattern(`^yum\s+install\s`), "yum install", Whitelisted},
	}
}

// defaultBlacklist returns patterns for clearly malicious behavior.
func defaultBlacklist() []Pattern {
	return []Pattern{
		{compilePattern(`/etc/shadow`), "access to shadow password file", Blacklisted},
		{compilePattern(`/etc/passwd.*\s+ modifications`), "passwd file modification", Blacklisted},
		{compilePattern(`wget\s+.*\|.*bash`), "remote script pipe to bash (reverse shell)", Blacklisted},
		{compilePattern(`curl\s+.*\|.*bash`), "remote script pipe to bash (reverse shell)", Blacklisted},
		{compilePattern(`nc\s+-e\s`), "netcat reverse shell", Blacklisted},
		{compilePattern(`/dev/tcp/`), "bash tcp device (reverse shell)", Blacklisted},
		{compilePattern(`curl\s+http://[a-f0-9.:]+\.sh`), "downloading script from IP", Blacklisted},
		{compilePattern(`wget\s+http://[a-f0-9.:]+\.sh`), "downloading script from IP", Blacklisted},
		{compilePattern(`nmap\s+-sS`), "stealth scan", Blacklisted},
		{compilePattern(`nikto\s`), "web vulnerability scanner", Blacklisted},
		{compilePattern(`sqlmap\s`), "SQL injection scanner", Blacklisted},
		{compilePattern(`hydra\s`), "password brute force", Blacklisted},
		{compilePattern(`john\s+--wordlist`), "password cracking with wordlist", Blacklisted},
		{compilePattern(`hashcat\s+`), "password hash cracking", Blacklisted},
		{compilePattern(`metasploit`), "metasploit framework", Blacklisted},
		{compilePattern(`msfvenom`), "metasploit payload generator", Blacklisted},
		{compilePattern(`tcpdump\s+.*-i\s+any`), "packet capture on all interfaces", Blacklisted},
		{compilePattern(`tcpdump\s+.*-i\s+[a-z]+\s+-w`), "packet capture to file", Blacklisted},
		{compilePattern(`ettercap`), "ARP poisoning tool", Blacklisted},
		{compilePattern(`arpspoof`), "ARP spoofing", Blacklisted},
		{compilePattern(`chmod\s+[47][0-7]{3}\s+`), "suspicious chmod (setuid/setgid)", Blacklisted},
		{compilePattern(`chmod\s+u\+s`), "setuid bit modification", Blacklisted},
		{compilePattern(`chmod\s+777\s+/`), "world writable root", Blacklisted},
		{compilePattern(`sshd_config`), "sshd config modification", Blacklisted},
		{compilePattern(`known_hosts`), "manipulating known hosts", Blacklisted},
		{compilePattern(`authorized_keys`), "adding authorized key", Blacklisted},
		{compilePattern(`crontab\s+-e`), "editing crontab", Blacklisted},
		{compilePattern(`rm\s+-rf\s+/`), "recursive force delete root", Blacklisted},
		{compilePattern(`dd\s+if=.*of=/dev/`), "direct disk write", Blacklisted},
		{compilePattern(`mkfs\.`), "formatting filesystem", Blacklisted},
		{compilePattern(`fdisk\s+-l`), "partition table read", Blacklisted},
		{compilePattern(`cat\s+/proc/scan`), "scanning for malware", Blacklisted},
		{compilePattern(`chattr\s+-i`), "immutable file change", Blacklisted},
		{compilePattern(`export\s+PATH=.*:.*/tmp`), "tmp in PATH (trojan risk)", Blacklisted},
		{compilePattern(`eval\s+.*\$`), "eval with variable", Blacklisted},
		{compilePattern(`base64\s+-d\s+.*\|.*sh`), "encoded shell execution", Blacklisted},
		{compilePattern(`bash\s+-i`), "interactive bash", Blacklisted},
		{compilePattern(`/bin/sh\s+-i`), "interactive shell", Blacklisted},
	}
}

// defaultGreylist returns patterns for potentially suspicious behavior that needs AI analysis.
func defaultGreylist() []Pattern {
	return []Pattern{
		{compilePattern(`curl\s+`), "curl command", Greylisted},
		{compilePattern(`wget\s+`), "wget download", Greylisted},
		{compilePattern(`bash\s+`), "bash execution", Greylisted},
		{compilePattern(`sh\s+-c\s+`), "shell execution", Greylisted},
		{compilePattern(`python[23]?\s+-m\s+`), "python module execution", Greylisted},
		{compilePattern(`perl\s+-e`), "perl inline execution", Greylisted},
		{compilePattern(`ruby\s+-e`), "ruby inline execution", Greylisted},
		{compilePattern(`php\s+-r`), "php inline execution", Greylisted},
		{compilePattern(`exec\s+`), "exec command", Greylisted},
		{compilePattern(`sudo\s+`), "sudo command", Greylisted},
		{compilePattern(`su\s+`), "switch user", Greylisted},
		{compilePattern(`chmod\s+[47][0-7][0-7]\s`), "suspicious chmod", Greylisted},
		{compilePattern(`chown\s+`), "change ownership", Greylisted},
		{compilePattern(`useradd`), "user creation", Greylisted},
		{compilePattern(`userdel`), "user deletion", Greylisted},
		{compilePattern(`usermod`), "user modification", Greylisted},
		{compilePattern(`groupadd`), "group creation", Greylisted},
		{compilePattern(`passwd\s+`), "password change", Greylisted},
		{compilePattern(`/tmp/`), "temp directory access", Greylisted},
		{compilePattern(`/var/tmp/`), "temp directory access", Greylisted},
		{compilePattern(`curl\s+.*\.(sh|py pl)\s*\|`), "script from network pipe", Greylisted},
		{compilePattern(`>\s+/dev/sd`), "writing to block device", Greylisted},
		{compilePattern(`nslookup\s+`), "DNS lookup", Greylisted},
		{compilePattern(`dig\s+`), "DNS query", Greylisted},
		{compilePattern(`host\s+`), "DNS lookup", Greylisted},
		{compilePattern(`iptables\s+-A`), "adding iptables rule", Greylisted},
		{compilePattern(`iptables\s+-t`), "modifying iptables table", Greylisted},
		{compilePattern(`firewall-cmd`), "firewall command", Greylisted},
		{compilePattern(`ufw\s+`), "ufw firewall", Greylisted},
		{compilePattern(`openssl\s+`), "openssl operations", Greylisted},
		{compilePattern(`ssh\s+-i\s+`), "SSH with identity file", Greylisted},
		{compilePattern(`scp\s+-i\s+`), "SCP with identity file", Greylisted},
		{compilePattern(`git\s+clone\s+`), "git clone", Greylisted},
		{compilePattern(`curl\s+.*api\.`), "API call", Greylisted},
		{compilePattern(`wget\s+.*\.exe`), "downloading executable", Greylisted},
		{compilePattern(`curl\s+.*\.exe`), "downloading executable", Greylisted},
	}
}

func (m *Matcher) String() string {
	return fmt.Sprintf("Matcher{whitelist: %d, blacklist: %d, greylist: %d}",
		len(m.whitelist), len(m.blacklist), len(m.greylist))
}
