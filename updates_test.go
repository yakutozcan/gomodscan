package main

import (
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

func TestDecodeModules(t *testing.T) {
	got, err := DecodeModules(strings.NewReader(`{"Path":"root"}
{"Path":"example.com/shared","Version":"v1.0.0","Update":{"Version":"v1.2.0"}}`))
	if err != nil || len(got) != 2 || got["example.com/shared"].Update.Version != "v1.2.0" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, input := range []string{`{`, `{"Path":"bad","Error":{"Err":"offline"}}`, `{"Path":"bad","Replace":{"Error":{"Err":"missing"}}}`} {
		if _, err := DecodeModules(strings.NewReader(input)); err == nil {
			t.Fatalf("expected error for %s", input)
		}
	}
}

func TestUpdateKind(t *testing.T) {
	for _, tc := range []struct{ from, to, want string }{{"v1.0.0", "v2.0.0", "major"}, {"v1.0.0", "v1.1.0", "minor"}, {"v1.0.0", "v1.0.1", "patch"}, {"v1.0.0", "v1.0.0", "current"}, {"v1.1.0", "v1.0.0", "current"}, {"bad", "v1.0.0", "unknown"}, {"v1.0.0-rc.1", "v1.0.0", "patch"}} {
		if got := UpdateKind(tc.from, tc.to); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}

func TestUpdateCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	bin := t.TempDir()
	script := `#!/bin/sh
[ "$GOFLAGS" = "-mod=mod" ] || exit 2
[ "$GOTOOLCHAIN" = "auto" ] || exit 3
case "$*" in
 "list -m -json -u -retracted all") ;;
 "list -m -json example.com/shared@latest") case "$PWD" in */metadatafailure) exit 1;; esac; printf '%s\n' '{"Path":"example.com/shared","Version":"v1.3.0","GoVersion":"1.25.0","Time":"2026-09-09T00:00:00Z"}'; exit 0;;
 *) exit 4;;
esac
case "$PWD" in
 */failure) echo offline >&2; exit 1;;
 */slow) exec sleep 5;;
esac
printf '%s\n' '{"Path":"example.com/shared","Version":"v1.2.0","Update":{"Version":"v1.3.0"}}'
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOFLAGS", "-broken")
	t.Setenv("GOTOOLCHAIN", "local")
	var modules []*Module
	root := t.TempDir()
	for _, name := range []string{"success", "failure", "slow", "metadatafailure"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		modules = append(modules, &Module{Dir: dir, Requires: []Dependency{{Path: "example.com/shared", Version: "v1.2.0"}}})
	}
	CheckUpdates(context.Background(), modules, time.Second, log.New(io.Discard, "", 0))
	if modules[0].UpdateCount != 1 || modules[0].Requires[0].UpdateKind != "minor" || modules[0].Requires[0].LatestGoVersion != "1.25.0" {
		t.Fatalf("success: %+v", modules[0])
	}
	missing := modules[3].Requires[0]
	if missing.LatestVersion != "" || missing.UpdateKind != "unknown" || missing.MetadataError == "" {
		t.Fatalf("failed metadata presented as latest: %+v", missing)
	}
	for _, m := range modules[1:3] {
		if m.UpdateStatus != "unavailable" || m.UpdateError == "" {
			t.Fatalf("failure: %+v", m)
		}
	}
}
