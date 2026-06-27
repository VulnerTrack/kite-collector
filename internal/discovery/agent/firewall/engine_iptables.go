package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// iptablesCollector enumerates rules via `iptables-save`. We pick
// iptables-save over iterating per-chain `iptables -L` because:
//   - Single-syscall fetch of the full ruleset (atomic snapshot).
//   - Stable, machine-parseable text format documented in iptables(8).
//   - Available since iptables 1.4 — supported on every Linux distro
//     in service.
//
// We do NOT distinguish IPv4 vs IPv6 ruleset; ip6tables-save lands in a
// follow-up. The current iptables-save covers the v4 path which carries
// the bulk of CWE-732 findings.
type iptablesCollector struct {
	run      runner
	lookPath pathLookup
	binary   string
}

// runner / pathLookup are the test seams.
type (
	runner     func(ctx context.Context, name string, args ...string) ([]byte, error)
	pathLookup func(string) (string, error)
)

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //#nosec G204 -- name is LookPath-resolved, args fixed
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("exec %s: %w", name, err)
	}
	return out, nil
}

// NewIPTablesCollector returns a collector backed by iptables-save. When
// the binary isn't on PATH, Collect returns empty (not error) so the
// multi-engine chain falls through.
func NewIPTablesCollector() Collector {
	return &iptablesCollector{
		run:      defaultRunner,
		lookPath: exec.LookPath,
		binary:   "iptables-save",
	}
}

func (c *iptablesCollector) Name() string { return "iptables-save" }

func (c *iptablesCollector) Collect(ctx context.Context) ([]Rule, error) {
	if _, err := c.lookPath(c.binary); err != nil {
		return []Rule{}, nil //nolint:nilerr // missing binary = "not applicable", not an error
	}
	raw, err := c.run(ctx, c.binary)
	if err != nil {
		return []Rule{}, fmt.Errorf("%s: %w", c.binary, err)
	}
	rules := parseIPTablesSave(string(raw))
	if len(rules) > MaxRules {
		rules = rules[:MaxRules]
	}
	for i := range rules {
		rules[i].RuleHash = HashRule(rules[i])
	}
	SortRules(rules)
	return rules, nil
}

// parseIPTablesSave parses the `iptables-save` output format. Only -A
// (append) rule lines are converted — comments, table headers (*filter),
// chain policies (:INPUT ACCEPT), and the terminator (COMMIT) are
// skipped. Rules without a -j target are skipped (no actionable verdict).
//
// Example input:
//
//	*filter
//	:INPUT ACCEPT [0:0]
//	:FORWARD DROP [0:0]
//	-A INPUT -i lo -j ACCEPT
//	-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
//	-A INPUT -p tcp --dport 5432 -s 0.0.0.0/0 -j ACCEPT
//	COMMIT
func parseIPTablesSave(raw string) []Rule {
	var out []Rule
	priority := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") || strings.HasPrefix(line, ":") ||
			strings.EqualFold(line, "COMMIT") {
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		r, ok := parseIPTablesRule(line)
		if !ok {
			continue
		}
		r.Priority = priority
		out = append(out, r)
		priority++
	}
	return out
}

// parseIPTablesRule converts one `-A <CHAIN> ... -j <TARGET>` line.
// The token grammar is small: alternating -flag value pairs. Unknown
// flags are accumulated into Extras so audit rules that care about
// state-matching etc. don't lose information.
func parseIPTablesRule(line string) (Rule, bool) {
	tokens := strings.Fields(line)
	if len(tokens) < 4 || tokens[0] != "-A" {
		return Rule{}, false
	}
	r := Rule{
		Engine: EngineIPTables,
		Chain:  tokens[1],
	}
	switch strings.ToUpper(tokens[1]) {
	case "INPUT", "PREROUTING":
		r.Direction = DirectionIn
	case "OUTPUT", "POSTROUTING":
		r.Direction = DirectionOut
	case "FORWARD":
		r.Direction = DirectionForward
	default:
		r.Direction = DirectionUnknown
	}

	var extras []string
	i := 2
	for i < len(tokens) {
		flag := tokens[i]
		val := ""
		if i+1 < len(tokens) {
			val = tokens[i+1]
		}
		switch flag {
		case "-p":
			r.Proto = val
			i += 2
		case "-s":
			r.SrcCIDR = ensureCIDR(val)
			i += 2
		case "-d":
			r.DstCIDR = ensureCIDR(val)
			i += 2
		case "--sport":
			r.SrcPort = val
			i += 2
		case "--dport":
			r.DstPort = val
			i += 2
		case "-i":
			r.IfaceIn = val
			i += 2
		case "-o":
			r.IfaceOut = val
			i += 2
		case "-j":
			r.Action = NormalizeAction(val)
			i += 2
		case "-m":
			// Match module — pass through to extras to keep audit context.
			extras = append(extras, flag, val)
			i += 2
		default:
			// Unknown flag — preserve it (single token if no value follows).
			extras = append(extras, flag)
			i++
		}
	}
	r.Extras = strings.Join(extras, " ")
	if r.Action == "" {
		r.Action = ActionUnknown
	}
	return r, true
}

// ensureCIDR appends /32 (or /128 for v6) when the value is a bare IP.
// iptables-save emits bare IPs as a shorthand for /32; normalising keeps
// the rule_hash stable across iptables versions that started/stopped
// emitting the mask.
func ensureCIDR(s string) string {
	if s == "" || strings.ContainsRune(s, '/') {
		return s
	}
	if strings.ContainsRune(s, ':') {
		return s + "/128"
	}
	return s + "/32"
}
