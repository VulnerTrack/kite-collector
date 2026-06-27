package parsers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"regexp"
)

// MixExsParser handles mix.exs files.
// Extracts deps via regex — no Elixir evaluation.
type MixExsParser struct{}

func (p *MixExsParser) Patterns() []string { return []string{"mix.exs"} }
func (p *MixExsParser) Ecosystem() string  { return "elixir" }

// Matches: {:name, "~> 1.0"}  {:name, ">= 0.0.0"}  {:name, github: "..."}
var mixDepRe = regexp.MustCompile(`\{:(\w+)\s*,\s*"([^"]*)"`)

func (p *MixExsParser) Parse(_ context.Context, path string, content []byte) (*ParseResult, error) {
	result := &ParseResult{ManifestPath: path}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		matches := mixDepRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			result.Dependencies = append(result.Dependencies, Dependency{
				Name:    m[1],
				Version: cleanVersion(m[2]),
				Vendor:  m[1],
				Scope:   "runtime",
				Direct:  true,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan mix.exs: %w", err)
	}

	return result, nil
}
