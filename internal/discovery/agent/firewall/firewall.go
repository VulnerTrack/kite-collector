// Package firewall enumerates active host-firewall rules from any
// installed engine (iptables, nftables, pf, Windows Firewall, ufw,
// firewalld). The schema is normalised across engines so a single CWE-732
// audit query can find permissive rules regardless of which engine
// produced them.
//
// Every collector is **read-only** — it queries rule tables, never
// inserts, deletes, flushes, or modifies any chain. Read-only is enforced
// by guideline 4.2 of the kite-collector project.
//
// Rule rows feed the CWE/CAPEC audit pipeline:
//
//   - CWE-732 (Incorrect Permission Assignment) — accept rules with
//     src_cidr='0.0.0.0/0' AND dst_port in (22, 3389, 5432, …) are
//     findings on internet-facing hosts.
//   - CWE-284 (Improper Access Control) — joined with host_listeners by
//     dst_port, this surfaces the full attack-path: "this port is bound
//     AND the firewall lets the internet reach it".
//   - Drift detection — `rule_hash` change between scans → security-
//     policy modification event.
package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// MaxRules bounds per-scan output. A hardened server has 20-200 rules; a
// router with policy NAT might have thousands. The 8192 ceiling protects
// the SQLite write path from runaway rule sets.
const MaxRules = 8192

// Engine is the source-of-record for a rule row. Pinned to the
// host_firewall_rules.engine CHECK enum.
type Engine string

const (
	EngineIPTables  Engine = "iptables"
	EngineNFTables  Engine = "nftables"
	EnginePF        Engine = "pf"
	EngineWindowsFW Engine = "windows-firewall"
	EngineUFW       Engine = "ufw"
	EngineFirewalld Engine = "firewalld"
	EngineUnknown   Engine = "unknown"
)

// Direction classifies traffic flow relative to the host. Pinned to the
// host_firewall_rules.direction CHECK enum.
type Direction string

const (
	DirectionIn      Direction = "in"
	DirectionOut     Direction = "out"
	DirectionForward Direction = "forward"
	DirectionUnknown Direction = "unknown"
)

// Action is the normalised verdict. Pinned to the
// host_firewall_rules.action CHECK enum.
type Action string

const (
	ActionAccept  Action = "accept"
	ActionDrop    Action = "drop"
	ActionReject  Action = "reject"
	ActionLog     Action = "log"
	ActionJump    Action = "jump"
	ActionReturn  Action = "return"
	ActionUnknown Action = "unknown"
)

// Rule is the cross-engine record produced by every collector. Mirrors
// the host_firewall_rules column shape.
type Rule struct {
	Engine    Engine    `json:"engine"`
	Chain     string    `json:"chain,omitempty"`
	Direction Direction `json:"direction"`
	Action    Action    `json:"action"`
	Proto     string    `json:"proto,omitempty"`
	SrcCIDR   string    `json:"src_cidr,omitempty"`
	SrcPort   string    `json:"src_port,omitempty"`
	DstCIDR   string    `json:"dst_cidr,omitempty"`
	DstPort   string    `json:"dst_port,omitempty"`
	IfaceIn   string    `json:"iface_in,omitempty"`
	IfaceOut  string    `json:"iface_out,omitempty"`
	Extras    string    `json:"extras,omitempty"`
	RuleHash  string    `json:"rule_hash"`
	Priority  int       `json:"priority,omitempty"`
}

// Collector is the read-only contract every engine implementation
// satisfies.
type Collector interface {
	// Name returns a stable identifier for telemetry.
	Name() string
	// Collect enumerates rules from this engine. Read-only. Returns
	// empty slice when the engine isn't installed/active — callers can
	// fall through to the next collector in the chain.
	Collect(ctx context.Context) ([]Rule, error)
}

// NormalizeAction maps engine-specific verdict strings to our pinned
// enum. iptables uses uppercase (`ACCEPT`/`DROP`/`REJECT`), nftables
// uses lowercase, pf uses `pass`/`block`/`block return`, Windows uses
// `Allow`/`Block`.
func NormalizeAction(raw string) Action {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "accept", "allow", "pass":
		return ActionAccept
	case "drop", "deny", "block":
		return ActionDrop
	case "reject", "block return":
		return ActionReject
	case "log":
		return ActionLog
	case "jump":
		return ActionJump
	case "return":
		return ActionReturn
	case "":
		return ActionUnknown
	}
	return ActionUnknown
}

// NormalizeDirection maps engine-specific direction tokens to our pinned
// enum. iptables chain names map cleanly: INPUT → in, OUTPUT → out,
// FORWARD → forward. nft hooks: input/output/forward map identically.
// pf: in / out keywords; default in.
func NormalizeDirection(raw string) Direction {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "in", "input":
		return DirectionIn
	case "out", "output":
		return DirectionOut
	case "forward":
		return DirectionForward
	}
	return DirectionUnknown
}

// HashRule returns a stable sha256 fingerprint of a rule's material fields
// so re-discovery upserts cleanly. The hash deliberately EXCLUDES the
// Priority field because rule reordering without content change is still
// the same logical rule.
func HashRule(r Rule) string {
	// Canonical form: pipe-delimited concatenation of normalised fields.
	// Avoid JSON to keep hash stable across struct-field-reorder refactors.
	canon := strings.Join([]string{
		string(r.Engine), r.Chain, string(r.Direction), string(r.Action),
		strings.ToLower(r.Proto),
		r.SrcCIDR, r.SrcPort, r.DstCIDR, r.DstPort,
		r.IfaceIn, r.IfaceOut, r.Extras,
	}, "|")
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}

// IsPermissive reports whether a rule grants access from any source — the
// CWE-732 signal. Conservative: a missing SrcCIDR is treated as ANY because
// most engines omit it as a shorthand for the universal default.
func IsPermissive(r Rule) bool {
	if r.Action != ActionAccept {
		return false
	}
	switch r.SrcCIDR {
	case "", "0.0.0.0/0", "::/0", "any":
		return true
	}
	return false
}

// SortRules returns a deterministic ordering: by engine, chain, priority,
// then rule hash for tie-break.
func SortRules(rs []Rule) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Engine != rs[j].Engine {
			return rs[i].Engine < rs[j].Engine
		}
		if rs[i].Chain != rs[j].Chain {
			return rs[i].Chain < rs[j].Chain
		}
		if rs[i].Priority != rs[j].Priority {
			return rs[i].Priority < rs[j].Priority
		}
		return rs[i].RuleHash < rs[j].RuleHash
	})
}
