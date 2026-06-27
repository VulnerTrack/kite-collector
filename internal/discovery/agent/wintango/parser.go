package wintango

import (
	"bufio"
	"bytes"
	"strings"
)

// EmpresaMetadata captures the CUIT + denominación the
// Empresas.cnf / Empresas.ini files expose. Both vendors use
// loose INI grammar with `KEY=VALUE` lines (case-insensitive
// keys) and `[section]` headers we ignore.
type EmpresaMetadata struct {
	CuitRaw      string
	Denominacion string
}

// ParseEmpresaConfig pulls `cuit` / `denominacion` (and
// vendor-specific synonyms) out of an Empresas.cnf or
// Empresas.ini body.
func ParseEmpresaConfig(body []byte) EmpresaMetadata {
	var out EmpresaMetadata
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		val = strings.Trim(val, `"'`)
		if val == "" {
			continue
		}
		switch key {
		case "cuit", "nrocuit", "cuit_empresa", "cuit-empresa":
			if out.CuitRaw == "" {
				out.CuitRaw = val
			}
		case "denominacion", "razonsocial", "razon_social", "razon-social",
			"nombre", "empresa", "denominacion_empresa":
			if out.Denominacion == "" {
				out.Denominacion = val
			}
		}
	}
	return out
}
