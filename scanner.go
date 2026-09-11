package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
)

type ScanOptions struct {
	Workers int           `json:"workers"`
	Exclude []string      `json:"exclude"`
	Depth   int           `json:"depth"`
	Timeout time.Duration `json:"timeout"`
}

// Scan walks roots without following symbolic links. Overlapping roots are deduplicated.
// Root directories have depth zero; depth one includes their immediate children.
func Scan(ctx context.Context, roots []string, opts ScanOptions, logger *log.Logger) ScanResult {
	result := ScanResult{}
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	type scanJob struct {
		path, root, relative string
		destination          *Module
	}
	jobs := make(chan scanJob, workers)
	var pool sync.WaitGroup
	for range workers {
		pool.Go(func() {
			for job := range jobs {
				if ctx.Err() != nil {
					job.destination.Error = ctx.Err().Error()
					continue
				}
				logger.Printf("Parsing %s", job.path)
				m := ParseModule(job.path)
				m.Root, m.RelativeDir = job.root, job.relative
				readGit(ctx, m, opts.Timeout)
				*job.destination = *m
			}
		})
	}
	// Only the walker owns discovery maps and the result slices. Each worker owns
	// one module pointer, so completion order cannot change report ordering.
	defer func() { close(jobs); pool.Wait() }()

	excluded, seen, workSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, name := range opts.Exclude {
		excluded[strings.TrimSpace(name)] = true
	}
	for _, root := range roots {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors, ScanError{Path: root, Error: ctx.Err().Error()})
			break
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			result.Errors = append(result.Errors, ScanError{Path: root, Error: err.Error()})
			continue
		}
		result.Roots = append(result.Roots, abs)
		info, err := os.Lstat(abs)
		if err != nil || !info.IsDir() {
			message := "root is not a directory (symbolic links are not followed)"
			if err != nil {
				message = err.Error()
			}
			result.Errors = append(result.Errors, ScanError{Path: abs, Error: message})
			continue
		}
		err = filepath.WalkDir(abs, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				if filepath.Base(path) == "go.mod" && !seen[path] {
					seen[path] = true
					dir := filepath.Dir(path)
					rel, _ := filepath.Rel(abs, dir)
					result.Modules = append(result.Modules, &Module{Dir: dir, Root: abs, RelativeDir: rel, Error: walkErr.Error(), UpdateStatus: "unchecked"})
				} else {
					result.Errors = append(result.Errors, ScanError{Path: path, Error: walkErr.Error()})
				}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if entry.IsDir() {
				if excluded[entry.Name()] {
					return fs.SkipDir
				}
				rel, _ := filepath.Rel(abs, path)
				level := 0
				if rel != "." {
					level = len(strings.Split(rel, string(filepath.Separator)))
				}
				if opts.Depth > 0 && level > opts.Depth {
					return fs.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			if entry.Name() == "go.work" && !workSeen[path] {
				workSeen[path] = true
				w := Workspace{Path: path}
				data, err := os.ReadFile(path)
				if err == nil {
					_, err = modfile.ParseWork(path, data, nil)
				}
				if err != nil {
					w.Error = err.Error()
				}
				result.Workspaces = append(result.Workspaces, w)
			}
			if entry.Name() != "go.mod" || seen[path] {
				return nil
			}
			seen[path] = true
			dir := filepath.Dir(path)
			relative, _ := filepath.Rel(abs, dir)
			m := &Module{Dir: dir, Root: abs, RelativeDir: relative, UpdateStatus: "unchecked"}
			result.Modules = append(result.Modules, m)
			select {
			case jobs <- scanJob{path: path, root: abs, relative: relative, destination: m}:
			case <-ctx.Done():
				m.Error = ctx.Err().Error()
				return ctx.Err()
			}
			return nil
		})
		if err != nil {
			result.Errors = append(result.Errors, ScanError{Path: abs, Error: err.Error()})
		}
	}
	return result
}

func ParseModule(path string) *Module {
	m := &Module{Dir: filepath.Dir(path), UpdateStatus: "unchecked"}
	m.HasGoSum = regularFile(filepath.Join(m.Dir, "go.sum"))
	if info, err := os.Lstat(filepath.Join(m.Dir, "vendor")); err == nil {
		m.HasVendor = info.IsDir()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		m.Error = fmt.Sprintf("read go.mod: %v", err)
		return m
	}
	f, err := modfile.Parse(path, data, nil)
	if err != nil {
		m.Error = fmt.Sprintf("parse go.mod: %v", err)
		return m
	}
	if f.Module == nil {
		m.Error = "parse go.mod: missing module directive"
		return m
	}
	m.Path = f.Module.Mod.Path
	if f.Go != nil {
		m.GoVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		m.Toolchain = f.Toolchain.Name
	}
	for _, r := range f.Require {
		m.Requires = append(m.Requires, Dependency{Path: r.Mod.Path, Version: r.Mod.Version, Indirect: r.Indirect, UpdateKind: "unchecked"})
		if r.Indirect {
			m.IndirectCount++
		} else {
			m.DirectCount++
		}
	}
	for _, r := range f.Replace {
		m.Replaces = append(m.Replaces, Replacement{OldPath: r.Old.Path, OldVersion: r.Old.Version, NewPath: r.New.Path, NewVersion: r.New.Version})
	}
	for _, e := range f.Exclude {
		m.Excludes = append(m.Excludes, ModuleVersion{Path: e.Mod.Path, Version: e.Mod.Version})
	}
	for _, r := range f.Retract {
		m.Retracts = append(m.Retracts, Retraction{Low: r.Low, High: r.High, Rationale: r.Rationale})
	}
	for _, t := range f.Tool {
		m.Tools = append(m.Tools, t.Path)
	}
	return m
}

func regularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func readGit(parent context.Context, m *Module, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := func(args ...string) string {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = m.Dir
		cmd.WaitDelay = time.Second
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	m.GitBranch = command("rev-parse", "--abbrev-ref", "HEAD")
	m.LastCommit = command("log", "-1", "--format=%cI", "--", ".")
}
