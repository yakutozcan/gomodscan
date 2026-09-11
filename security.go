package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// OSV response types retain only fields used by the report.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}
type OSVEvent struct {
	Fixed string `json:"fixed"`
}
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}
type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges"`
}
type OSVRecord struct {
	ID        string        `json:"id"`
	Aliases   []string      `json:"aliases"`
	Summary   string        `json:"summary"`
	Withdrawn string        `json:"withdrawn"`
	Affected  []OSVAffected `json:"affected"`
}
type OSVResponse struct {
	Vulns         []OSVRecord `json:"vulns"`
	NextPageToken string      `json:"next_page_token"`
}
type OSVQuery struct {
	Package   OSVPackage `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvClient struct {
	endpoint string
	client   *http.Client
	cache    sync.Map
	flights  singleflight.Group
}

func (c *osvClient) query(ctx context.Context, path, version string) ([]Vulnerability, error) {
	key := path + "@" + version
	if cached, ok := c.cache.Load(key); ok {
		return cached.([]Vulnerability), nil
	}
	ch := c.flights.DoChan(key, func() (any, error) {
		if cached, ok := c.cache.Load(key); ok {
			return cached, nil
		}
		result, err := c.fetch(ctx, path, version)
		if err == nil {
			c.cache.Store(key, result)
		}
		return result, err
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.([]Vulnerability), nil
	}
}

func (c *osvClient) fetch(ctx context.Context, path, version string) ([]Vulnerability, error) {
	var result []Vulnerability
	seenIDs, seenTokens := map[string]bool{}, map[string]bool{}
	token := ""
	for {
		payload, _ := json.Marshal(OSVQuery{Package: OSVPackage{Name: path, Ecosystem: "Go"}, Version: version, PageToken: token})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := c.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("OSV request failed: %w", err)
		}
		var page OSVResponse
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return nil, fmt.Errorf("OSV returned HTTP %d", response.StatusCode)
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 32<<20))
		err = decoder.Decode(&page)
		if err == nil {
			var extra any
			if trailing := decoder.Decode(&extra); trailing != io.EOF {
				err = fmt.Errorf("unexpected trailing OSV response data")
			}
		}
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode OSV response: %w", err)
		}
		for _, record := range page.Vulns {
			if record.ID == "" {
				return nil, fmt.Errorf("OSV record has no ID")
			}
			if record.Withdrawn != "" || seenIDs[record.ID] {
				continue
			}
			seenIDs[record.ID] = true
			v := Vulnerability{ID: record.ID, Aliases: record.Aliases, Summary: record.Summary, URL: "https://osv.dev/vulnerability/" + url.PathEscape(record.ID)}
			fixed := map[string]bool{}
			for _, affected := range record.Affected {
				if affected.Package.Name != path || affected.Package.Ecosystem != "Go" {
					continue
				}
				for _, r := range affected.Ranges {
					if r.Type != "SEMVER" {
						continue
					}
					for _, event := range r.Events {
						if event.Fixed == "" {
							continue
						}
						value := "v" + strings.TrimPrefix(event.Fixed, "v")
						if semver.IsValid(value) {
							fixed[value] = true
						}
					}
				}
			}
			for value := range fixed {
				v.FixedVersions = append(v.FixedVersions, value)
			}
			sort.Slice(v.FixedVersions, func(i, j int) bool { return semver.Compare(v.FixedVersions[i], v.FixedVersions[j]) < 0 })
			result = append(result, v)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
		if seenTokens[token] {
			return nil, fmt.Errorf("OSV returned a repeated pagination token")
		}
		seenTokens[token] = true
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func CheckSecurity(ctx context.Context, modules []*Module, timeout time.Duration, logger *log.Logger) {
	client := &osvClient{endpoint: "https://api.osv.dev/v1/query", client: &http.Client{Timeout: timeout}}
	checkSecurity(ctx, modules, timeout, logger, client, privatePatterns)
}

// Read effective Go configuration, including persisted `go env -w` settings.
// If it cannot be read we fail closed instead of disclosing a private module name.
func privatePatterns(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "-json", "GOPRIVATE", "GONOPROXY", "GONOSUMDB")
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("read Go privacy settings: %w", err)
	}
	var settings map[string]string
	if err = json.Unmarshal(out, &settings); err != nil {
		return "", fmt.Errorf("decode Go privacy settings: %w", err)
	}
	return strings.Join([]string{settings["GOPRIVATE"], settings["GONOPROXY"], settings["GONOSUMDB"]}, ","), nil
}

func checkSecurity(parent context.Context, modules []*Module, timeout time.Duration, logger *log.Logger, client *osvClient, privacy func(context.Context, string) (string, error)) {
	group := new(errgroup.Group)
	group.SetLimit(runtime.NumCPU())
	for _, m := range modules {
		group.Go(func() error {
			ctx, cancel := context.WithTimeout(parent, timeout)
			defer cancel()
			patterns, privacyErr := privacy(ctx, m.Dir)
			for i := range m.Requires {
				d := &m.Requires[i]
				current := d.Version
				if d.ResolvedVersion != "" {
					current = d.ResolvedVersion
				}
				d.Security = SecurityResult{Version: current}
				replaced := d.Replaced
				for _, r := range m.Replaces {
					if r.OldPath == d.Path && (r.OldVersion == "" || r.OldVersion == current) {
						replaced = true
					}
				}
				switch {
				case replaced:
					d.Security.Status = "replaced"
				case privacyErr != nil:
					d.Security.Status = "unavailable"
					d.Security.Error = privacyErr.Error()
				case module.MatchPrefixPatterns(patterns, d.Path):
					d.Security.Status = "private"
				case !semver.IsValid(current):
					d.Security.Status = "unavailable"
					d.Security.Error = "cannot query OSV: invalid module version"
				default:
					logger.Printf("Checking OSV for %s@%s", d.Path, current)
					d.Security = querySecurity(ctx, client, d.Path, current)
					if semver.IsValid(d.LatestVersion) {
						if d.LatestVersion == current {
							d.TargetSecurity = d.Security
						} else {
							d.TargetSecurity = querySecurity(ctx, client, d.Path, d.LatestVersion)
						}
					}
				}
			}
			return nil
		})
	}
	_ = group.Wait()
}

func querySecurity(ctx context.Context, client *osvClient, path, version string) SecurityResult {
	result := SecurityResult{Status: "checked", Version: version}
	vulns, err := client.query(ctx, path, version)
	if err != nil {
		result.Status = "unavailable"
		result.Error = err.Error()
	} else {
		result.Vulnerabilities = vulns
	}
	return result
}
