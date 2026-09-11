package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestParseModule(t *testing.T) {
	m := ParseModule("testdata/tree/go.mod")
	if m.Error != "" {
		t.Fatal(m.Error)
	}
	if m.Path != "example.com/root" || m.GoVersion != "1.24.0" || m.Toolchain != "go1.24.1" {
		t.Fatalf("directives: %+v", m)
	}
	if m.DirectCount != 1 || m.IndirectCount != 1 || !m.Requires[1].Indirect {
		t.Fatalf("requirements: %+v", m)
	}
	if len(m.Replaces) != 1 || m.Replaces[0].NewPath != "../local" || len(m.Excludes) != 1 || len(m.Retracts) != 1 || m.Retracts[0].High != "v0.2.0" || len(m.Tools) != 1 {
		t.Fatalf("directives: %+v", m)
	}
	if !m.HasGoSum || !m.HasVendor {
		t.Fatal("missing filesystem metadata")
	}
}

func TestParseErrors(t *testing.T) {
	for _, path := range []string{"testdata/tree/broken/go.mod", "testdata/missing/go.mod"} {
		if m := ParseModule(path); m.Error == "" {
			t.Fatalf("expected error for %s", path)
		}
	}
}

func TestScanDepthExclusionsAndOverlap(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	for _, test := range []struct{ depth, want int }{{0, 4}, {1, 3}, {2, 4}} {
		result := Scan(context.Background(), []string{"testdata/tree", "testdata/tree/nested"}, ScanOptions{Exclude: []string{"vendor"}, Depth: test.depth, Timeout: time.Second}, logger)
		// The second root makes deeper visible at depth one as well.
		if test.depth == 1 {
			test.want = 4
		}
		if len(result.Modules) != test.want || len(result.Workspaces) != 1 {
			t.Fatalf("depth %d: modules=%d workspaces=%d", test.depth, len(result.Modules), len(result.Workspaces))
		}
	}
	result := Scan(context.Background(), []string{"testdata/tree"}, ScanOptions{Exclude: []string{"vendor"}, Depth: 1}, logger)
	if len(result.Modules) != 3 {
		t.Fatalf("depth one found %d modules", len(result.Modules))
	}
}

func TestScanSymlinksAndBadRoot(t *testing.T) {
	root := t.TempDir()
	target, _ := filepath.Abs("testdata/tree")
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(filepath.Join(target, "go.mod"), filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	result := Scan(context.Background(), []string{root, filepath.Join(root, "linked"), filepath.Join(root, "missing")}, ScanOptions{}, log.New(io.Discard, "", 0))
	if len(result.Modules) != 0 || len(result.Errors) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestMalformedWorkspaceAndMissingModuleDirective(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("invalid directive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("go 1.24.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := Scan(context.Background(), []string{root}, ScanOptions{}, log.New(io.Discard, "", 0))
	if len(result.Workspaces) != 1 || result.Workspaces[0].Error == "" || len(result.Modules) != 1 || result.Modules[0].Error == "" {
		t.Fatalf("expected recorded errors: %+v", result)
	}
}

func TestParallelScanPreservesDiscoveryOrder(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	roots := []string{"testdata/tree", "testdata/tree/nested"}
	sequential := Scan(context.Background(), roots, ScanOptions{Exclude: []string{"vendor"}, Workers: 1}, logger)
	parallel := Scan(context.Background(), roots, ScanOptions{Exclude: []string{"vendor"}, Workers: 4}, logger)
	if !reflect.DeepEqual(sequential, parallel) {
		t.Fatalf("parallel scan changed discovery order or metadata:\n%+v\n%+v", sequential, parallel)
	}
}

func TestParallelScanCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	root, bin := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nexec sleep 10\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for i := 0; i < 20; i++ {
		dir := filepath.Join(root, fmt.Sprint(i))
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\ngo 1.24.0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	finished := make(chan ScanResult, 1)
	go func() {
		finished <- Scan(ctx, []string{root}, ScanOptions{Workers: 2, Timeout: time.Minute}, log.New(io.Discard, "", 0))
	}()
	select {
	case result := <-finished:
		if ctx.Err() == nil || len(result.Errors) == 0 {
			t.Fatal("expected cancellation to be recorded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan workers did not stop after cancellation")
	}
}
