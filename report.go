package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/mod/semver"
)

type Module struct {
	Reachability  ReachabilityResult `json:"reachability"`
	Baseline      []CommandResult    `json:"baseline"`
	Path          string             `json:"path"`
	Dir           string             `json:"dir"`
	Root          string             `json:"root"`
	RelativeDir   string             `json:"relative_dir"`
	GoVersion     string             `json:"go_version"`
	Toolchain     string             `json:"toolchain"`
	Requires      []Dependency       `json:"requires"`
	Replaces      []Replacement      `json:"replaces"`
	Excludes      []ModuleVersion    `json:"excludes"`
	Retracts      []Retraction       `json:"retracts"`
	Tools         []string           `json:"tools"`
	HasGoSum      bool               `json:"has_go_sum"`
	HasVendor     bool               `json:"has_vendor"`
	GitBranch     string             `json:"git_branch"`
	LastCommit    string             `json:"last_commit"`
	DirectCount   int                `json:"direct_count"`
	IndirectCount int                `json:"indirect_count"`
	UpdateCount   int                `json:"update_count"`
	UpdateStatus  string             `json:"update_status"`
	UpdateError   string             `json:"update_error,omitempty"`
	Error         string             `json:"error,omitempty"`
}
type Dependency struct {
	Trial           UpgradeTrial   `json:"trial"`
	ResolvedVersion string         `json:"resolved_version,omitempty"`
	LatestVersion   string         `json:"latest_version,omitempty"`
	LatestGoVersion string         `json:"latest_go_version,omitempty"`
	LatestTime      *time.Time     `json:"latest_time,omitempty"`
	MetadataError   string         `json:"metadata_error,omitempty"`
	Deprecated      string         `json:"deprecated,omitempty"`
	Retracted       []string       `json:"retracted,omitempty"`
	Replaced        bool           `json:"replaced"`
	Compatibility   Compatibility  `json:"compatibility"`
	ReleaseStatus   string         `json:"release_status"`
	Security        SecurityResult `json:"security"`
	TargetSecurity  SecurityResult `json:"target_security"`

	Path          string `json:"path"`
	Version       string `json:"version"`
	Indirect      bool   `json:"indirect"`
	UpdateVersion string `json:"update_version,omitempty"`
	UpdateKind    string `json:"update_kind"`
}
type Compatibility struct {
	Risk    string   `json:"risk"`
	Reasons []string `json:"reasons"`
}
type SecurityResult struct {
	Status          string          `json:"status"`
	Version         string          `json:"version,omitempty"`
	Error           string          `json:"error,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
type Vulnerability struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	Summary       string   `json:"summary"`
	URL           string   `json:"url"`
	FixedVersions []string `json:"fixed_versions"`
}
type ActionItem struct {
	Project  string `json:"project"`
	Dir      string `json:"dir"`
	Path     string `json:"path"`
	Current  string `json:"current"`
	Target   string `json:"target"`
	Priority int    `json:"priority"`
	Reason   string `json:"reason"`
}
type ModuleVersion struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}
type Replacement struct {
	OldPath    string `json:"old_path"`
	OldVersion string `json:"old_version"`
	NewPath    string `json:"new_path"`
	NewVersion string `json:"new_version"`
}
type Retraction struct {
	Low       string `json:"low"`
	High      string `json:"high"`
	Rationale string `json:"rationale"`
}
type Workspace struct {
	Path  string `json:"path"`
	Error string `json:"error,omitempty"`
}
type ScanError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}
type ScanResult struct {
	Roots      []string    `json:"roots"`
	Modules    []*Module   `json:"modules"`
	Workspaces []Workspace `json:"workspaces"`
	Errors     []ScanError `json:"errors"`
}
type VersionUsage struct {
	Version  string   `json:"version"`
	Projects []string `json:"projects"`
}
type Conflict struct {
	Path     string         `json:"path"`
	Versions []VersionUsage `json:"versions"`
}
type GoDistribution struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
	Percent int    `json:"percent"`
}
type Report struct {
	ScanResult
	CheckedVulnerabilities bool             `json:"checked_vulnerabilities"`
	VulnerableDependencies int              `json:"vulnerable_dependencies"`
	SecurityChecked        int              `json:"security_checked"`
	SecurityUnavailable    int              `json:"security_unavailable"`
	Actions                []ActionItem     `json:"actions"`
	ScannedAt              string           `json:"scanned_at"`
	CheckedUpdates         bool             `json:"checked_updates"`
	UniqueDependencies     int              `json:"unique_dependencies"`
	UpdatableDependencies  int              `json:"updatable_dependencies"`
	Conflicts              []Conflict       `json:"conflicts"`
	GoVersions             []GoDistribution `json:"go_versions"`
}

func BuildReport(result ScanResult, checked bool) Report {
	r := Report{ScanResult: result, ScannedAt: time.Now().Format(time.RFC3339), CheckedUpdates: checked}
	r.Errors = append([]ScanError(nil), result.Errors...)
	unique, updated := map[string]bool{}, map[string]bool{}
	versions := map[string]int{}
	direct := map[string]map[string][]string{}
	for _, m := range r.Modules {
		if m.Reachability.Error != "" {
			r.Errors = append(r.Errors, ScanError{Path: m.Dir, Error: m.Reachability.Error})
		}
		for _, step := range m.Baseline {
			if step.Error != "" {
				r.Errors = append(r.Errors, ScanError{Path: m.Dir, Error: step.Command + ": " + step.Error})
			}
		}
		for _, d := range m.Requires {
			if d.Trial.Error != "" {
				r.Errors = append(r.Errors, ScanError{Path: m.Dir + " → " + d.Path, Error: d.Trial.Error})
			}
		}
		if m.Error != "" {
			r.Errors = append(r.Errors, ScanError{Path: m.Dir, Error: m.Error})
		} else {
			version := m.GoVersion
			if version == "" {
				version = "Belirtilmedi"
			}
			versions[version]++
		}
		if m.UpdateError != "" {
			r.Errors = append(r.Errors, ScanError{Path: m.Dir, Error: m.UpdateError})
		}
		for _, d := range m.Requires {
			unique[d.Path] = true
			if d.UpdateKind == "major" || d.UpdateKind == "minor" || d.UpdateKind == "patch" {
				updated[d.Path] = true
			}
			if d.Indirect {
				continue
			}
			if direct[d.Path] == nil {
				direct[d.Path] = map[string][]string{}
			}
			direct[d.Path][d.Version] = append(direct[d.Path][d.Version], fmt.Sprintf("%s (%s)", m.Path, m.Dir))
		}
	}
	for _, w := range r.Workspaces {
		if w.Error != "" {
			r.Errors = append(r.Errors, ScanError{Path: w.Path, Error: w.Error})
		}
	}
	r.UniqueDependencies, r.UpdatableDependencies = len(unique), len(updated)
	for version, count := range versions {
		r.GoVersions = append(r.GoVersions, GoDistribution{Version: version, Count: count, Percent: count * 100 / max(1, len(r.Modules))})
	}
	sort.Slice(r.GoVersions, func(i, j int) bool {
		return semver.Compare("v"+r.GoVersions[i].Version, "v"+r.GoVersions[j].Version) < 0
	})
	for path, usage := range direct {
		if len(usage) < 2 {
			continue
		}
		conflict := Conflict{Path: path}
		for version, projects := range usage {
			sort.Strings(projects)
			conflict.Versions = append(conflict.Versions, VersionUsage{Version: version, Projects: projects})
		}
		sort.Slice(conflict.Versions, func(i, j int) bool {
			return semver.Compare(conflict.Versions[i].Version, conflict.Versions[j].Version) < 0
		})
		r.Conflicts = append(r.Conflicts, conflict)
	}
	sort.Slice(r.Conflicts, func(i, j int) bool { return r.Conflicts[i].Path < r.Conflicts[j].Path })
	buildInsights(&r)
	return r
}

//go:embed template.html
var reportTemplate string

func RenderReport(w io.Writer, report Report) error {
	t, err := template.New("report").Funcs(template.FuncMap{
		"securityStatus": securityLabel,
		"checkLabel":     checkLabel,
		"riskLabel":      riskLabel,
		"releaseLabel":   releaseLabel,
		"headers": func() []string {
			return []string{"Modül", "Dizin", "Go", "Toolchain", "Direct", "Indirect", "Güncellenebilir"}
		},
		"fallback": func(s string) string {
			if s == "" {
				return "—"
			}
			return s
		},
		"yesno": func(b bool) string {
			if b {
				return "Var"
			}
			return "Yok"
		},
		"status": func(s string) string {
			switch s {
			case "major":
				return "Major"
			case "minor":
				return "Minor"
			case "patch":
				return "Patch"
			case "current":
				return "Güncel"
			case "replaced":
				return "Replace uygulanmış"
			case "unknown":
				return "Bilinmiyor"
			default:
				return "Kontrol edilmedi"
			}
		},
	}).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}
	return t.Execute(w, report)
}

// WriteReport atomically replaces the output only after rendering succeeds.
func WriteReport(path string, report Report) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".gomodscan-*.html")
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer os.Remove(file.Name())
	err = RenderReport(file, report)
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("render report: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("save report: %w", err)
	}
	return nil
}
