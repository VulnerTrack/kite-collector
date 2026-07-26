// cpan.go
package software

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type CPAN struct{}

func NewCPAN() *CPAN { return &CPAN{} }

func (c *CPAN) Name() string { return "cpan" }

func (c *CPAN) Available() bool {
	_, err := exec.LookPath("cpan")
	return err == nil
}

func (c *CPAN) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "cpan", "-l")
	if err != nil {
		return nil, fmt.Errorf("cpan -l: %w", err)
	}
	return ParseCPANOutput(string(out)), nil
}

// cpanModuleName matches a Perl module name: one or more identifier
// components joined by "::" (perlmod). It is the discriminator that tells a
// real "Module::Name\tversion" record apart from the diagnostic text cpan(1)
// interleaves on stdout, so prose banners are never mistaken for packages.
var cpanModuleName = regexp.MustCompile(`^\w+(?:::\w+)*$`)

// ParseCPANOutput parses the output of `cpan -l`.
//
// `cpan -l` prints one installed module per line as "Module::Name\tversion"
// (version is the literal "undef" when the module exposes no $VERSION). It
// also writes diagnostic banners to the same stdout stream — most notably
// "Loading internal logger. Log::Log4perl recommended for better logging"
// when CPAN.pm falls back to its built-in logger, plus assorted "Reading
// '.../Metadata'..." notices. Those banners are not package records; they are
// expected, benign output that varies by environment, so treating them as
// parse errors produces spurious warnings on every scan.
//
// Therefore a line is accepted only when it is a well-formed
// "<perl-module-name>\t<version>" record; any other line is cpan's own
// chatter and is skipped silently rather than reported as an error.
func ParseCPANOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))

	for scanner.Scan() {
		line := scanner.Text()

		name, version, ok := strings.Cut(line, "\t")
		if !ok || !cpanModuleName.MatchString(name) {
			// Diagnostic banner / notice from cpan(1), not a module record.
			continue
		}

		if version == "undef" {
			version = ""
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cpan",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "perl"),
		})
	}

	return result
}

var _ Collector = (*CPAN)(nil)
