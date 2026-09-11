package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, current, target, projectGo, targetGo, want string }{
		{"patch", "v1.0.0", "v1.0.1", "1.24.0", "1.23.0", "low"},
		{"minor", "v1.0.0", "v1.1.0", "1.24.0", "1.24.0", "low"},
		{"major", "v1.0.0", "v2.0.0", "1.24.0", "1.24.0", "high"},
		{"unstable", "v0.1.0", "v0.1.1", "1.24.0", "1.24.0", "high"},
		{"prerelease", "v1.0.0-rc.1", "v1.0.0", "1.24.0", "1.24.0", "high"},
		{"go bump", "v1.0.0", "v1.0.1", "1.24.0", "1.25.0", "high"},
		{"missing Go", "v1.0.0", "v1.0.1", "1.24.0", "", "unknown"},
		{"current", "v1.0.0", "v1.0.0", "1.24.0", "1.24.0", "none"},
		{"unknown", "v1.0.0", "", "1.24.0", "1.24.0", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AssessCompatibility(Dependency{Version: tc.current, LatestVersion: tc.target, LatestGoVersion: tc.targetGo}, tc.projectGo)
			if got.Risk != tc.want || len(got.Reasons) == 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestReleaseAgeAndPriority(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	recent, old := now.Add(-time.Hour), now.Add(-96*time.Hour)
	m := &Module{GoVersion: "1.24.0", Requires: []Dependency{
		{Path: "young", Version: "v1.0.0", LatestVersion: "v1.0.1", LatestGoVersion: "1.24.0", LatestTime: &recent, UpdateKind: "patch"},
		{Path: "old", Version: "v1.0.0", LatestVersion: "v1.0.1", LatestGoVersion: "1.24.0", LatestTime: &old, UpdateKind: "patch"},
		{Path: "security", Version: "v1.0.0", LatestVersion: "v1.0.1", LatestGoVersion: "1.24.0", LatestTime: &recent, UpdateKind: "patch", Security: SecurityResult{Status: "checked", Vulnerabilities: []Vulnerability{{ID: "GO-TEST"}}}},
	}}
	AssessDependencies([]*Module{m}, 72*time.Hour, now)
	if m.Requires[0].ReleaseStatus != "young" || m.Requires[1].ReleaseStatus != "mature" {
		t.Fatalf("age: %+v", m.Requires)
	}
	report := BuildReport(ScanResult{Modules: []*Module{m}}, true)
	if len(report.Actions) != 3 || report.Actions[0].Path != "security" || report.Actions[0].Priority != 1 || report.Actions[1].Path != "young" {
		t.Fatalf("priority: %+v", report.Actions)
	}
}

func TestSecurityReportEscaping(t *testing.T) {
	attack := `<script>alert(1)</script>`
	m := &Module{Requires: []Dependency{{Path: "example.com/pkg", LatestVersion: "v1.2.0", Compatibility: Compatibility{Risk: "high", Reasons: []string{attack}}, Security: SecurityResult{Status: "checked", Vulnerabilities: []Vulnerability{{ID: "GO-TEST", Summary: attack, URL: "javascript:alert(1)", FixedVersions: []string{"v1.1.0"}}}}}}}
	report := BuildReport(ScanResult{Modules: []*Module{m}}, true)
	var out bytes.Buffer
	if err := RenderReport(&out, report); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if strings.Contains(html, attack) || strings.Contains(html, `href="javascript:`) || !strings.Contains(html, "GO-TEST") || !strings.Contains(html, "En güncel sürüm") {
		t.Fatal("unsafe or missing report content")
	}
}

func TestExcludedTargetIsHighRisk(t *testing.T) {
	m := &Module{GoVersion: "1.24.0", Excludes: []ModuleVersion{{Path: "example.com/pkg", Version: "v1.0.1"}}, Requires: []Dependency{{Path: "example.com/pkg", Version: "v1.0.0", LatestVersion: "v1.0.1", LatestGoVersion: "1.24.0", UpdateKind: "patch"}}}
	AssessDependencies([]*Module{m}, 0, time.Now())
	if m.Requires[0].Compatibility.Risk != "high" {
		t.Fatal("excluded target not flagged")
	}
}
