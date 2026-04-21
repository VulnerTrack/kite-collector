package dashboard

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"time"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// writeCSVHeader writes report traceability metadata as CSV comment lines.
func writeCSVHeader(w io.Writer, rc ReportContext) {
	_, _ = fmt.Fprintf(w, "# Report ID: %s\n", rc.ReportID)
	_, _ = fmt.Fprintf(w, "# Generated: %s (%s)\n", rc.GeneratedAtUTC, rc.GeneratedAtLocal)
	if rc.ScanRunID != "" {
		_, _ = fmt.Fprintf(w, "# Scan Run: %s\n", rc.ScanRunID)
	}
	_, _ = fmt.Fprintf(w, "# Application: %s %s (commit %s)\n", rc.AppName, rc.AppVersion, rc.Commit)
	_, _ = fmt.Fprintf(w, "# Host: %s (%s/%s)\n", rc.Hostname, rc.OS, rc.Arch)
	_, _ = fmt.Fprintf(w, "# Database: %s\n", rc.DBPath)
}

// exportAssetsCSV writes all assets as CSV with report headers.
func exportAssetsCSV(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	writeCSVHeader(w, rc)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{
		"hostname", "asset_type", "os_family", "os_version",
		"is_authorized", "is_managed", "environment", "owner",
		"discovery_source", "first_seen_at", "last_seen_at",
	})

	assets, err := st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	for _, a := range assets {
		_ = cw.Write([]string{
			a.Hostname,
			string(a.AssetType),
			a.OSFamily,
			a.OSVersion,
			string(a.IsAuthorized),
			string(a.IsManaged),
			a.Environment,
			a.Owner,
			a.DiscoverySource,
			a.FirstSeenAt.Format("2006-01-02T15:04:05Z"),
			a.LastSeenAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	return nil
}

// exportSoftwareCSV writes all software as CSV with report headers.
func exportSoftwareCSV(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	writeCSVHeader(w, rc)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{
		"hostname", "software_name", "version", "vendor",
		"cpe23", "package_manager",
	})

	assets, err := st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	for _, a := range assets {
		sw, swErr := st.ListSoftware(ctx, a.ID)
		if swErr != nil {
			continue
		}
		for _, s := range sw {
			_ = cw.Write([]string{
				a.Hostname,
				s.SoftwareName,
				s.Version,
				s.Vendor,
				s.CPE23,
				s.PackageManager,
			})
		}
	}

	return nil
}

// exportFindingsCSV writes all findings as CSV with report headers.
func exportFindingsCSV(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	writeCSVHeader(w, rc)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	_ = cw.Write([]string{
		"check_id", "severity", "cwe_id", "title", "auditor",
	})

	findings, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	for _, f := range findings {
		_ = cw.Write([]string{
			f.CheckID,
			string(f.Severity),
			f.CWEID,
			f.Title,
			f.Auditor,
		})
	}

	return nil
}

// exportTableCSV writes an arbitrary introspected table as CSV. The table name
// is validated by Store.DescribeTable before any SQL is issued, so an unknown
// table yields store.ErrUnknownTable without leaking the identifier into SQL.
func exportTableCSV(w io.Writer, ctx context.Context, st store.Store, rc ReportContext, name string) error {
	schema, err := st.DescribeTable(ctx, name)
	if err != nil {
		return fmt.Errorf("describe table %q: %w", name, err)
	}

	writeCSVHeader(w, rc)

	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := make([]string, len(schema.Columns))
	for i, c := range schema.Columns {
		header[i] = c.Name
	}
	_ = cw.Write(header)

	rows, _, err := st.ListRows(ctx, store.RowsFilter{
		Table: name,
		Limit: store.IntrospectionRowLimit,
	})
	if err != nil {
		return fmt.Errorf("list rows %q: %w", name, err)
	}

	for _, row := range rows {
		record := make([]string, len(row.Columns))
		for i, c := range row.Columns {
			record[i] = stringifyCSV(c.Value)
		}
		_ = cw.Write(record)
	}

	return nil
}

// stringifyCSV converts a driver-returned cell value into a CSV-safe string.
// Binary blobs are hex-encoded; timestamps use RFC3339-ish format; nil yields
// an empty string.
func stringifyCSV(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return fmt.Sprintf("%x", x)
	case time.Time:
		return x.Format("2006-01-02T15:04:05Z")
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}
