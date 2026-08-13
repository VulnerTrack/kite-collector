package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultOTLPEndpoint = "https://otel.vulnertrack.io"

type legacyOTLPValue struct {
	StringValue *string `json:"stringValue,omitempty"`
}

type legacyOTLPKeyValue struct {
	Key   string          `json:"key"`
	Value legacyOTLPValue `json:"value"`
}

type legacyOTLPLogRecord struct {
	Body                 legacyOTLPValue      `json:"body"`
	TimeUnixNano         string               `json:"timeUnixNano"`
	ObservedTimeUnixNano string               `json:"observedTimeUnixNano"`
	SeverityNumber       int                  `json:"severityNumber"`
	SeverityText         string               `json:"severityText"`
	EventName            string               `json:"eventName,omitempty"`
	TraceID              string               `json:"traceId,omitempty"`
	SpanID               string               `json:"spanId,omitempty"`
	Attributes           []legacyOTLPKeyValue `json:"attributes"`
}

type legacyOTLPPayload struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []legacyOTLPKeyValue `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name    string `json:"name"`
				Version string `json:"version,omitempty"`
			} `json:"scope"`
			LogRecords []legacyOTLPLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type legacyOTLPClient struct {
	endpoint string
	http     *http.Client
	resource []legacyOTLPKeyValue
}

func syncLatestInventory(ctx context.Context, dir string) error {
	snapshot, err := loadLatestInventory(dir)
	if err != nil {
		return err
	}
	needed, err := inventoryNeedsSync(dir, snapshot.CollectedAt)
	if err != nil || !needed {
		return err
	}
	client, err := newLegacyOTLPClient(dir, snapshot)
	if err != nil {
		return err
	}
	records, err := buildInventoryOTLPRecords(snapshot, client.resource)
	if err != nil {
		return err
	}
	if err := client.sendRecords(ctx, records); err != nil {
		return err
	}
	return markInventorySynced(dir, snapshot.CollectedAt)
}

func newLegacyOTLPClient(dir string, snapshot *inventorySnapshot) (*legacyOTLPClient, error) {
	certPath := filepath.Join(dir, "agent.pem")
	keyPath := filepath.Join(dir, "agent-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load OTLP client identity: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caPEM, readErr := os.ReadFile(caPath); readErr == nil {
		pool.AppendCertsFromPEM(caPEM)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: http.ProxyFromEnvironment}
	endpoint, err := normalizeLegacyOTLPEndpoint(os.Getenv("KITE_OTLP_ENDPOINT"))
	if err != nil {
		return nil, err
	}
	leaf, err := loadLeafCertificate(certPath)
	if err != nil {
		return nil, err
	}
	hostname := snapshot.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	assetID := stableInventoryUUID(leaf.Subject.CommonName + "\x00" + strings.ToLower(hostname))
	osVersion := inventoryOSVersion(snapshot)
	resource := map[string]string{
		"service.name":           "kite-collector",
		"service.version":        version,
		"service.namespace":      "vulnertrack",
		"service.instance.id":    assetID,
		"host.id":                assetID,
		"host.name":              hostname,
		"host.arch":              "x86",
		"os.type":                "windows",
		"os.name":                "windows",
		"os.version":             osVersion,
		"agent.id":               assetID,
		"agent.type":             "kite-collector",
		"tenant.id":              certificateTenant(leaf),
		"deployment.environment": "production",
		"kite.contract.version":  "1.1",
	}
	return &legacyOTLPClient{
		endpoint: endpoint,
		http:     &http.Client{Transport: transport, Timeout: 60 * time.Second},
		resource: mapOTLPAttributes(resource),
	}, nil
}

func normalizeLegacyOTLPEndpoint(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultOTLPEndpoint
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid OTLP endpoint %q", raw)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("unsupported OTLP endpoint scheme %q", parsed.Scheme)
	}
	parsed.Path = "/v1/logs"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func loadLeafCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid agent certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificateTenant(cert *x509.Certificate) string {
	for _, org := range cert.Subject.Organization {
		if isUUID(org) {
			return strings.ToLower(strings.TrimSpace(org))
		}
	}
	return "unknown"
}

func inventoryOSVersion(snapshot *inventorySnapshot) string {
	if row := firstRow(snapshot, "operating_system"); row != nil {
		if value := firstValue(row, "Version", "Caption"); value != "" {
			return value
		}
	}
	return "6.1"
}

func buildInventoryOTLPRecords(snapshot *inventorySnapshot, resource []legacyOTLPKeyValue) ([]legacyOTLPLogRecord, error) {
	assetID := otlpResourceValue(resource, "agent.id")
	scanID := randomUUID()
	traceID := strings.ReplaceAll(scanID, "-", "")
	now := snapshot.CollectedAt.UTC()
	common := map[string]string{
		"machine_id":                        assetID,
		"scan_run_id":                       scanID,
		"hostname":                          snapshot.Hostname,
		"machine_type":                      "workstation",
		"os_family":                         "windows",
		"os_version":                        inventoryOSVersion(snapshot),
		"discovery_source":                  "agent",
		"is_authorized":                     "unknown",
		"is_managed":                        "managed",
		"severity":                          "info",
		"event.domain":                      "security",
		"security.machine.uid":              assetID,
		"security.scan.uid":                 scanID,
		"security.machine.name":             snapshot.Hostname,
		"security.machine.type":             "workstation",
		"security.machine.os.name":          "windows",
		"security.machine.os.version":       inventoryOSVersion(snapshot),
		"security.machine.authorization":    "unknown",
		"security.machine.managed_status":   "managed",
		"security.machine.discovery.source": "agent",
		"security.machine.first_seen":       now.Format(time.RFC3339Nano),
	}
	software := make([]map[string]string, 0)
	for _, category := range []string{"installed_software_native", "installed_software_wow64"} {
		for _, row := range snapshot.Categories[category] {
			software = append(software, map[string]string{
				"software_name": row["name"], "vendor": row["publisher"],
				"version": row["version"], "package_manager": "windows_registry",
			})
		}
	}
	summaryBody := map[string]interface{}{
		"hostname": snapshot.Hostname, "machine_type": "workstation",
		"os_family": "windows", "os_version": inventoryOSVersion(snapshot),
		"discovery_source": "agent", "is_authorized": "unknown", "is_managed": "managed",
		"first_seen_at": now.Format(time.RFC3339Nano), "last_seen_at": now.Format(time.RFC3339Nano),
		"software": software, "tags": []string{"windows-legacy", "windows-7", "x86"},
	}
	attributes := cloneStrings(common)
	attributes["event_type"] = "MachineUpdated"
	attributes["event_name"] = "kite.machine.updated"
	attributes["event.name"] = "machine.changed"
	records := []legacyOTLPLogRecord{newInventoryOTLPRecord(summaryBody, attributes, now, traceID)}

	categoryNames := inventoryCategoryNames(snapshot)
	for category := range snapshot.Errors {
		if _, exists := snapshot.Categories[category]; !exists {
			categoryNames = append(categoryNames, category)
		}
	}
	sort.Strings(categoryNames)
	categoryNames = uniqueStrings(categoryNames)
	for _, category := range categoryNames {
		body := map[string]interface{}{
			"snapshot_id": scanID, "asset_id": assetID, "hostname": snapshot.Hostname,
			"collected_at": now.Format(time.RFC3339Nano), "category": category,
			"rows": snapshot.Categories[category], "error": snapshot.Errors[category],
		}
		categoryAttrs := cloneStrings(common)
		categoryAttrs["event_type"] = "WindowsInventoryCategory"
		categoryAttrs["event_name"] = "kite.windows.inventory.category"
		// Keep the record inside the collector's RFC-0115 closed event-name
		// contract. The legacy event_type and JSON body provide the specialised
		// routing discriminator downstream.
		categoryAttrs["event.name"] = "machine.changed"
		records = append(records, newInventoryOTLPRecord(body, categoryAttrs, now, traceID))
	}
	return records, nil
}

func newInventoryOTLPRecord(body interface{}, attrs map[string]string, timestamp time.Time, traceID string) legacyOTLPLogRecord {
	encoded, _ := json.Marshal(body)
	bodyText := string(encoded)
	spanRaw := sha256.Sum256(append(encoded, byte(len(attrs))))
	return legacyOTLPLogRecord{
		Body:                 legacyOTLPValue{StringValue: &bodyText},
		TimeUnixNano:         strconv.FormatInt(timestamp.UnixNano(), 10),
		ObservedTimeUnixNano: strconv.FormatInt(time.Now().UnixNano(), 10),
		SeverityNumber:       9,
		SeverityText:         "info",
		EventName:            attrs["event_name"],
		TraceID:              traceID,
		SpanID:               hex.EncodeToString(spanRaw[:8]),
		Attributes:           mapOTLPAttributes(attrs),
	}
}

func (c *legacyOTLPClient) sendRecords(ctx context.Context, records []legacyOTLPLogRecord) error {
	const maxBatchBytes = 512 * 1024
	for start := 0; start < len(records); {
		end := start + 1
		for end <= len(records) {
			payload := c.payload(records[start:end])
			encoded, _ := json.Marshal(payload)
			if len(encoded) > maxBatchBytes && end > start+1 {
				end--
				break
			}
			if len(encoded) > maxBatchBytes || end == len(records) {
				break
			}
			end++
		}
		if err := c.sendBatch(ctx, records[start:end]); err != nil {
			return fmt.Errorf("send inventory records %d-%d: %w", start+1, end, err)
		}
		start = end
	}
	return nil
}

func (c *legacyOTLPClient) payload(records []legacyOTLPLogRecord) legacyOTLPPayload {
	var payload legacyOTLPPayload
	var resourceLog struct {
		Resource struct {
			Attributes []legacyOTLPKeyValue `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name    string `json:"name"`
				Version string `json:"version,omitempty"`
			} `json:"scope"`
			LogRecords []legacyOTLPLogRecord `json:"logRecords"`
		} `json:"scopeLogs"`
	}
	resourceLog.Resource.Attributes = c.resource
	var scopeLog struct {
		Scope struct {
			Name    string `json:"name"`
			Version string `json:"version,omitempty"`
		} `json:"scope"`
		LogRecords []legacyOTLPLogRecord `json:"logRecords"`
	}
	scopeLog.Scope.Name = "kite-collector.emitter"
	scopeLog.Scope.Version = version
	scopeLog.LogRecords = records
	resourceLog.ScopeLogs = append(resourceLog.ScopeLogs, scopeLog)
	payload.ResourceLogs = append(payload.ResourceLogs, resourceLog)
	return payload
}

func (c *legacyOTLPClient) sendBatch(ctx context.Context, records []legacyOTLPLogRecord) error {
	encoded, err := json.Marshal(c.payload(records))
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("OTLP returned %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return lastErr
		}
	}
	return lastErr
}

func mapOTLPAttributes(values map[string]string) []legacyOTLPKeyValue {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]legacyOTLPKeyValue, 0, len(keys))
	for _, key := range keys {
		value := values[key]
		result = append(result, legacyOTLPKeyValue{Key: key, Value: legacyOTLPValue{StringValue: &value}})
	}
	return result
}

func otlpResourceValue(attrs []legacyOTLPKeyValue, key string) string {
	for _, attr := range attrs {
		if attr.Key == key && attr.Value.StringValue != nil {
			return *attr.Value.StringValue
		}
	}
	return ""
}

func stableInventoryUUID(value string) string {
	digest := sha256.Sum256([]byte("kite-windows-inventory\x00" + value))
	bytes := digest[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x50
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return formatUUID(bytes)
}

func randomUUID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		digest := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
		copy(value, digest[:16])
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return formatUUID(value)
}

func formatUUID(value []byte) string {
	hexValue := hex.EncodeToString(value)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32]
}

func isUUID(value string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func cloneStrings(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
