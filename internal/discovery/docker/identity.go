package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// OCI annotations describe the declared immediate base. Modern/squashed images
// may omit both annotations and Parent; absence is kept explicit, never inferred
// from container names. Only this allowlist is emitted, not arbitrary labels/env.
func (c *dockerClient) imageIdentity(ctx context.Context, id string) map[string]string {
	facts := make(map[string]string)
	id, err := sanitizeImageID(id)
	if err != nil || id == "" {
		return facts
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	body, err := c.getLimited(ctx, "/images/"+id+"/json", 1<<20)
	if err != nil {
		return facts
	}
	var image struct {
		Parent string `json:"Parent"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal(body, &image) != nil {
		return facts
	}
	for annotation, tag := range map[string]string{
		"org.opencontainers.image.base.name":   "image_base_name",
		"org.opencontainers.image.base.digest": "image_base_digest",
	} {
		if value := image.Config.Labels[annotation]; value != "" && len(value) <= 512 {
			facts[tag] = value
		}
	}
	if image.Parent != "" && len(image.Parent) <= 128 {
		facts["image_parent_id"] = image.Parent
	}
	return facts
}

// Read os-release via the read-only archive endpoint. Never exec a command,
// start a stopped container, extract a tar to disk, or follow archive symlinks.
func (c *dockerClient) containerOSIdentity(ctx context.Context, id string) map[string]string {
	id, err := safenet.SanitizePathSegment(id)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		body, readErr := c.getLimited(ctx, "/containers/"+id+"/archive?path="+path, 128<<10)
		if readErr != nil {
			continue
		}
		reader := tar.NewReader(bytes.NewReader(body))
		header, headerErr := reader.Next()
		if headerErr != nil || header.Typeflag != tar.TypeReg || header.Size > 16<<10 {
			continue
		}
		data, fileErr := io.ReadAll(io.LimitReader(reader, 16<<10))
		if fileErr == nil {
			if facts := parseOSIdentity(data); len(facts) > 0 {
				return facts
			}
		}
	}
	return nil
}

func parseOSIdentity(data []byte) map[string]string {
	facts := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !ok {
			continue
		}
		tag, allowed := map[string]string{"ID": "os_id", "VERSION_ID": "os_version_id", "CPE_NAME": "os_cpe23"}[key]
		if !allowed {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"`) {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				continue
			}
			value = unquoted
		} else {
			value = strings.Trim(value, "'")
		}
		if value != "" && len(value) <= 512 {
			facts[tag] = value
		}
	}
	return facts
}
