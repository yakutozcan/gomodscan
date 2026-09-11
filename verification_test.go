package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureModule(t *testing.T) *Module {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.24.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &Module{Dir: dir, Path: "example.com/app", Requires: []Dependency{{Path: "example.com/dep", Version: "v1.0.0", LatestVersion: "v1.1.0", UpdateKind: "minor"}}}
}
func fakeVerificationGo(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	bin := t.TempDir()
	script := `#!/bin/sh
[ "$GOWORK" = off ] || exit 11
[ "$GOFLAGS" = -mod=mod ] || exit 12
case "$PWD" in *gomodscan-check-*) ;; *) echo source-modified; exit 13;; esac
case "$1" in
build) [ ! -f baseline-fail ] || exit 1;;
get) touch candidate; echo changed >> go.mod;;
test) if [ -f candidate ] && [ -f candidate-fail ]; then echo failure >&2; exit 1; fi
 echo '{"Action":"pass","Package":"example.com/app","Test":"TestApp"}'
 echo '{"Action":"pass","Package":"example.com/app"}' ;;
list) echo changed >> go.mod
 echo '{"Path":"example.com/dep","Version":"v1.0.0"}' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOWORK", "off")
}
func TestUpgradeTrialsAndSourcePreservation(t *testing.T) {
	fakeVerificationGo(t)
	for _, tc := range []struct{ name, marker, want string }{{"pass", "", "passed"}, {"baseline", "baseline-fail", "blocked"}, {"candidate", "candidate-fail", "failed"}} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureModule(t)
			if tc.marker != "" {
				os.WriteFile(filepath.Join(m.Dir, tc.marker), nil, 0600)
			}
			before, _ := os.ReadFile(filepath.Join(m.Dir, "go.mod"))
			CheckUpgradeTrials(context.Background(), []*Module{m}, 5*time.Second, 2, log.New(io.Discard, "", 0))
			if m.Requires[0].Trial.Status != tc.want {
				t.Fatalf("trial: %+v", m.Requires[0].Trial)
			}
			after, _ := os.ReadFile(filepath.Join(m.Dir, "go.mod"))
			if !bytes.Equal(before, after) {
				t.Fatal("source go.mod changed")
			}
			if _, err := os.Stat(filepath.Join(m.Dir, "candidate")); !os.IsNotExist(err) {
				t.Fatal("test files leaked into source")
			}
			if tc.want == "passed" && m.Requires[0].Trial.Steps[2].TestsRun != 1 {
				t.Fatal("test result not counted")
			}
		})
	}
}
func TestUpdateMetadataUsesCopy(t *testing.T) {
	fakeVerificationGo(t)
	m := fixtureModule(t)
	before, _ := os.ReadFile(filepath.Join(m.Dir, "go.mod"))
	CheckUpdatesInCopies(context.Background(), []*Module{m}, 5*time.Second, 1, log.New(io.Discard, "", 0))
	after, _ := os.ReadFile(filepath.Join(m.Dir, "go.mod"))
	if !bytes.Equal(before, after) {
		t.Fatal("metadata resolution modified source")
	}
	if m.UpdateStatus != "available" {
		t.Fatalf("metadata: %s", m.UpdateError)
	}
}
func TestCopyRejectsUnsupportedReferences(t *testing.T) {
	t.Setenv("GOWORK", "off")
	for _, kind := range []string{"workspace", "replace", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			m := fixtureModule(t)
			switch kind {
			case "workspace":
				os.WriteFile(filepath.Join(m.Dir, "go.work"), []byte("go 1.24.0"), 0600)
			case "replace":
				os.WriteFile(filepath.Join(m.Dir, "go.mod"), []byte("module example.com/app\ngo 1.24.0\nreplace example.com/dep => ../outside\n"), 0600)
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(m.Dir, "link")); err != nil {
					t.Skip(err)
				}
			}
			_, cleanup, err := copyModule(context.Background(), m)
			defer cleanup()
			if err == nil {
				t.Fatal("unsupported source accepted")
			}
		})
	}
}
func TestDecodeReachability(t *testing.T) {
	config := `{"config":{"protocol_version":"v1.0.0","scan_level":"symbol","scan_mode":"source","scanner_version":"test"}}`
	input := config + `{"finding":{"osv":"GO-1","trace":[{"module":"dep"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"dep","package":"dep/pkg"}]}}
{"finding":{"osv":"GO-1","fixed_version":"v1.1.0","trace":[{"module":"dep","package":"dep/pkg","function":"Unsafe"},{"module":"app","function":"Main"}]}}`
	result, err := DecodeReachability(strings.NewReader(input))
	if err != nil || len(result.Findings) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	for _, bad := range []string{"", `{}`, config + `{`, strings.Replace(config, "symbol", "module", 1)} {
		if _, err := DecodeReachability(strings.NewReader(bad)); err == nil {
			t.Fatal("invalid stream accepted")
		}
	}
}
func TestReachabilityCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	bin := t.TempDir()
	t.Setenv("GOWORK", "off")
	script := `#!/bin/sh
[ "$*" = "-json -scan=symbol ./..." ] || exit 2
case "$PWD" in *gomodscan-check-*) ;; *) exit 3;; esac
echo '{"config":{"protocol_version":"v1.0.0","scan_level":"symbol","scan_mode":"source"}}'
echo '{"finding":{"osv":"GO-TEST","trace":[{"module":"stdlib","package":"net/http","function":"Serve"}]}}'
`
	os.WriteFile(filepath.Join(bin, "govulncheck"), []byte(script), 0755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	m := fixtureModule(t)
	CheckReachability(context.Background(), []*Module{m}, time.Second, 1, log.New(io.Discard, "", 0))
	if m.Reachability.Status != "checked" || len(m.Reachability.Findings) != 1 {
		t.Fatalf("%+v", m.Reachability)
	}
	var html bytes.Buffer
	if err := RenderReport(&html, BuildReport(ScanResult{Modules: []*Module{m}}, false)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "GO-TEST") {
		t.Fatal("reachable finding missing in HTML")
	}
}
func TestVerificationTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "slow"), []byte("#!/bin/sh\nexec sleep 10\n"), 0755)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := runCheck(ctx, t.TempDir(), filepath.Join(bin, "slow"))
	if result.Status != "unavailable" {
		t.Fatalf("timeout: %+v", result)
	}
}
