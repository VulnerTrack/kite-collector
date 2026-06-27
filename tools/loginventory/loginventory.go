// Package loginventory walks every package that contains a logcodes.go
// file and extracts the declared LogCode constants (plus their doc
// comments) into a single Markdown catalog.
//
// The output is the single source of truth runbook authors, on-call
// engineers, and SIEM-rule authors consult when they need to know
// "what does code X mean and what should I do about it?". The
// generator is deterministic so the committed docs/LOG_CODES.md can
// be diffed in CI to catch contributors who add a code but forget to
// regenerate the catalog.
//
// Run via `go run ./tools/loginventory` from the repo root, or via
// the `loginventory.Generate` function from tests.
package loginventory

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Code captures one LogCode constant extracted from a package's
// logcodes.go file. Comment is the doc comment immediately preceding
// the const declaration (or empty when the constant was declared
// inside a block without its own doc comment).
type Code struct {
	Package    string // Go package name, e.g. "dashboard"
	Constant   string // Go identifier, e.g. "LogCodeEnrollUpsert"
	Value      string // The actual string literal, e.g. "dashboard.enroll.upsert_failed"
	Comment    string // Doc comment for this specific constant (may be empty)
	GroupLabel string // Most recent `// surface — description` group header above the constant
	File       string // Repo-relative source file path
}

// pkgGroup is one package's worth of extracted codes plus the metadata
// needed to render the catalog section. Hoisted from a local type in
// Generate so renderMarkdown can take the same named type as input.
type pkgGroup struct {
	dir         string
	packageName string
	codes       []Code
}

// Generate walks repoRoot for every `logcodes.go` file, parses each,
// and returns the rendered Markdown catalog. The output is
// deterministic: codes are grouped by package (alphabetical), then
// listed in the order they appear in the source file (which mirrors
// the surface grouping the package author chose).
func Generate(repoRoot string) ([]byte, error) {
	files, err := findLogcodesFiles(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("find logcodes.go files: %w", err)
	}

	groups := make([]pkgGroup, 0, len(files))
	for _, f := range files {
		codes, pkgName, err := parseLogcodes(f, repoRoot)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		if len(codes) == 0 {
			continue
		}
		groups = append(groups, pkgGroup{
			dir:         filepath.Dir(f),
			packageName: pkgName,
			codes:       codes,
		})
	}

	// Sort packages by their dir (repo-relative) for stable output.
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].dir < groups[j].dir
	})

	return renderMarkdown(groups, repoRoot), nil
}

// findLogcodesFiles walks repoRoot returning every regular file named
// `logcodes.go`. Hidden directories and the tools/ + vendor/ trees
// are skipped — the inventory describes shipped code, not generators
// or third-party dependencies.
func findLogcodesFiles(repoRoot string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "tools" || strings.HasPrefix(base, ".") {
				if path == repoRoot {
					return nil
				}
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) == "logcodes.go" {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// parseLogcodes parses one logcodes.go file and returns the LogCode
// constants declared in it, along with the package name.
//
// The parser looks for any `const ( … )` block; for each constant
// whose value is a *basic-lit string assignment, it captures the
// identifier name, the string value, and the doc comment text. Group
// labels are inferred from line comments inside the const block that
// follow the convention `// <surface> surface — <description>`.
func parseLogcodes(path, repoRoot string) ([]Code, string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, "", err
	}

	relPath, err := filepath.Rel(repoRoot, path)
	if err != nil {
		relPath = path
	}

	var out []Code
	var currentGroup string

	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vspec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			// Doc comments above a constant are treated as the group
			// header for that constant and every constant that follows
			// until another constant has its own Doc. Per-constant
			// inline annotations (e.g., `LogCodeFoo … // see note`) are
			// captured separately via vspec.Comment and become the row's
			// description.
			if vspec.Doc != nil {
				var lines []string
				for _, c := range vspec.Doc.List {
					text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
					if text == "" {
						continue
					}
					lines = append(lines, text)
				}
				if len(lines) > 0 {
					currentGroup = strings.Join(lines, " ")
				}
			}

			for i, name := range vspec.Names {
				if !strings.HasPrefix(name.Name, "LogCode") {
					continue
				}
				if i >= len(vspec.Values) {
					continue
				}
				lit, ok := vspec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unq, err := strconv.Unquote(lit.Value)
				if err != nil {
					continue
				}

				comment := ""
				if vspec.Comment != nil {
					var parts []string
					for _, c := range vspec.Comment.List {
						parts = append(parts, strings.TrimSpace(strings.TrimPrefix(c.Text, "//")))
					}
					comment = strings.Join(parts, " ")
				}

				out = append(out, Code{
					Package:    file.Name.Name,
					Constant:   name.Name,
					Value:      unq,
					Comment:    comment,
					GroupLabel: currentGroup,
					File:       filepath.ToSlash(relPath),
				})
			}
		}
	}

	return out, file.Name.Name, nil
}

// renderMarkdown formats the extracted codes into the catalog page.
//
// Layout:
//   - top-level heading + brief intro
//   - one H2 per package (with the source path linked)
//   - one Markdown table per package: Code | Constant | Description
func renderMarkdown(groups []pkgGroup, repoRoot string) []byte {
	var b bytes.Buffer
	b.WriteString("# Kite-collector log code catalog\n\n")
	b.WriteString("<!-- Generated by `go run ./tools/loginventory`. Do not edit by hand. -->\n\n")
	b.WriteString("Every kite-collector log call emits a `\"code\"` structured attribute. ")
	b.WriteString("Downstream tooling (Loki/Splunk queries, SIEM alert rules, on-call runbooks) ")
	b.WriteString("pivots on the code rather than parsing freeform message text — the code is the **stable identifier**, ")
	b.WriteString("the message is informational.\n\n")
	b.WriteString("Convention: `<namespace>.<surface>.<event>`. Codes are immutable once shipped — ")
	b.WriteString("renaming breaks any alert that filters on the old value. To deprecate a code, add a new one ")
	b.WriteString("and update the call site; never rename in place.\n\n")
	b.WriteString("To regenerate this file:\n\n```\ngo run ./tools/loginventory > docs/LOG_CODES.md\n```\n\n")

	total := 0
	for _, g := range groups {
		total += len(g.codes)
	}
	fmt.Fprintf(&b, "**Catalog size:** %d codes across %d packages.\n\n", total, len(groups))

	b.WriteString("---\n\n")

	for _, g := range groups {
		if len(g.codes) == 0 {
			continue
		}
		relDir, err := filepath.Rel(repoRoot, g.dir)
		if err != nil {
			relDir = g.dir
		}
		relDir = filepath.ToSlash(relDir)
		fmt.Fprintf(&b, "## `%s` (%s)\n\n", g.packageName, relDir)
		fmt.Fprintf(&b, "Source: [`%s/logcodes.go`](../%s/logcodes.go) · %d codes\n\n",
			relDir, relDir, len(g.codes))

		// Render any group headers as sub-sections so the table is
		// scannable when the constant list is long.
		var lastGroup string
		for _, c := range g.codes {
			if c.GroupLabel != lastGroup {
				if lastGroup != "" {
					b.WriteString("\n")
				}
				fmt.Fprintf(&b, "**%s**\n\n", c.GroupLabel)
				b.WriteString("| Code | Constant | Description |\n")
				b.WriteString("|---|---|---|\n")
				lastGroup = c.GroupLabel
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n",
				c.Value, c.Constant, mdEscape(c.Comment))
		}
		b.WriteString("\n")
	}

	return b.Bytes()
}

// mdEscape collapses newlines and escapes pipes inside markdown table
// cells so multi-line comments stay readable.
func mdEscape(s string) string {
	if s == "" {
		return "—"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", `\|`)
	return s
}
