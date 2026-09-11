package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOSVPaginationCacheAndFixedVersions(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid OSV request")
		}
		var q OSVQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
		}
		if q.Package.Name != "example.com/pkg" || q.Package.Ecosystem != "Go" || q.Version != "v1.0.0" {
			t.Errorf("query: %+v", q)
		}
		if q.PageToken == "" {
			io.WriteString(w, `{"vulns":[{"id":"GO-TEST-1","aliases":["CVE-TEST"],"summary":"bad <script>","affected":[{"package":{"name":"example.com/pkg","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.0"},{"fixed":"1.1.1"}]}]},{"package":{"name":"unrelated","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9.0.0"}]}]}]}],"next_page_token":"page2"}`)
		} else {
			io.WriteString(w, `{"vulns":[{"id":"GO-TEST-1"},{"id":"GO-WITHDRAWN","withdrawn":"2025-01-01"},{"id":"GO-TEST-2"}]}`)
		}
	}))
	defer server.Close()
	client := &osvClient{endpoint: server.URL, client: server.Client()}
	for range 2 {
		result, err := client.query(context.Background(), "example.com/pkg", "v1.0.0")
		if err != nil || len(result) != 2 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if strings.Join(result[0].FixedVersions, ",") != "v1.1.1,v1.2.0" {
			t.Fatalf("fixed versions: %+v", result)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("cache failed: %d calls", calls.Load())
	}
}

func TestOSVFailuresAreNotCleanResults(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{{"rate limit", "", 429}, {"server", "", 500}, {"malformed", "{", 200}, {"missing ID", `{"vulns":[{}]}`, 200}, {"pagination loop", `{"next_page_token":"again"}`, 200}, {"trailing", `{} {}`, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			client := &osvClient{endpoint: server.URL, client: server.Client()}
			result := querySecurity(context.Background(), client, "example.com/pkg", "v1.0.0")
			if result.Status != "unavailable" || result.Error == "" {
				t.Fatalf("false clean result: %+v", result)
			}
		})
	}
}

func TestSecurityCoverageAndTarget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var q OSVQuery
		json.NewDecoder(r.Body).Decode(&q)
		if q.Package.Name != "public.example/pkg" {
			t.Errorf("disclosed skipped module: %s", q.Package.Name)
		}
		if q.Version == "v1.1.0" {
			io.WriteString(w, `{"vulns":[{"id":"GO-CURRENT"}]}`)
		} else if q.Version == "v1.2.0" {
			io.WriteString(w, `{}`)
		} else {
			t.Errorf("wrong version: %s", q.Version)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	modules := []*Module{{Requires: []Dependency{
		{Path: "public.example/pkg", Version: "v1.0.0", ResolvedVersion: "v1.1.0", LatestVersion: "v1.2.0"},
		{Path: "private.example/team/pkg", Version: "v1.0.0", LatestVersion: "v2.0.0"},
		{Path: "local.example/pkg", Version: "v1.0.0"},
	}, Replaces: []Replacement{{OldPath: "local.example/pkg", NewPath: "../local"}}}}
	client := &osvClient{endpoint: server.URL, client: server.Client()}
	checkSecurity(context.Background(), modules, time.Second, log.New(io.Discard, "", 0), client, func(context.Context, string) (string, error) { return "private.example/*", nil })
	deps := modules[0].Requires
	if len(deps[0].Security.Vulnerabilities) != 1 || deps[0].TargetSecurity.Status != "checked" || len(deps[0].TargetSecurity.Vulnerabilities) != 0 {
		t.Fatalf("target comparison: %+v", deps[0])
	}
	if deps[1].Security.Status != "private" || deps[2].Security.Status != "replaced" || calls.Load() != 2 {
		t.Fatalf("coverage: %+v", deps)
	}
	report := BuildReport(ScanResult{Modules: modules}, true)
	if report.VulnerableDependencies != 1 || report.SecurityChecked != 1 || report.SecurityUnavailable != 2 || len(report.Actions) != 1 || report.Actions[0].Priority != 1 {
		t.Fatalf("report: %+v", report)
	}
}

func TestSecurityPrivacyFailureDoesNotSend(t *testing.T) {
	modules := []*Module{{Requires: []Dependency{{Path: "secret.example/pkg", Version: "v1.0.0"}}}}
	// No usable HTTP client: any request is a test failure.
	checkSecurity(context.Background(), modules, time.Second, log.New(io.Discard, "", 0), &osvClient{}, func(context.Context, string) (string, error) { return "", fmt.Errorf("privacy unavailable") })
	if modules[0].Requires[0].Security.Status != "unavailable" {
		t.Fatal("privacy failure ignored")
	}
}

func TestOSVTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer server.Close()
	client := &osvClient{endpoint: server.URL, client: server.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := querySecurity(ctx, client, "example.com/pkg", "v1.0.0")
	if result.Status != "unavailable" {
		t.Fatalf("timeout reported as clean: %+v", result)
	}
}
