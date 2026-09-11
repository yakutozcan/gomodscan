package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"
)

type CommandResult struct {
	Command   string `json:"command"`
	Status    string `json:"status"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	TestsRun  int    `json:"tests_run"`
	Truncated bool   `json:"truncated"`
}
type UpgradeTrial struct {
	Status string          `json:"status"`
	Target string          `json:"target,omitempty"`
	Error  string          `json:"error,omitempty"`
	Steps  []CommandResult `json:"steps"`
}

// Temporary copies isolate files, not the network or side effects of test code.
// Unsupported file references are rejected rather than silently testing a different project.
func copyModule(ctx context.Context, m *Module) (string, func(), error) {
	empty := func() {}
	if m.Error != "" {
		return "", empty, fmt.Errorf("invalid module: %s", m.Error)
	}
	if w := os.Getenv("GOWORK"); w != "" && w != "off" && w != "auto" {
		return "", empty, fmt.Errorf("explicit GOWORK is unsupported for isolated checks")
	}
	for dir := m.Dir; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, "go.work")); err == nil {
			return "", empty, fmt.Errorf("workspace modules are unsupported for isolated checks")
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	data, err := os.ReadFile(filepath.Join(m.Dir, "go.mod"))
	if err != nil {
		return "", empty, err
	}
	parsed, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", empty, err
	}
	for _, r := range parsed.Replace {
		if r.New.Version != "" {
			continue
		}
		clean := filepath.Clean(r.New.Path)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", empty, fmt.Errorf("external local replacement is unsupported: %s", r.New.Path)
		}
	}
	dest, err := os.MkdirTemp("", "gomodscan-check-")
	if err != nil {
		return "", empty, err
	}
	cleanup := func() { os.RemoveAll(dest) }
	err = filepath.WalkDir(m.Dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, err := filepath.Rel(m.Dir, path)
		if err != nil {
			return err
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(dest, rel), 0700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in module copy: %s", rel)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		source, err := os.Open(path)
		if err != nil {
			return err
		}
		defer source.Close()
		target, err := os.OpenFile(filepath.Join(dest, rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()|0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(target, contextReader{ctx: ctx, reader: source})
		closeErr := target.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		cleanup()
		return "", empty, err
	}
	return dest, cleanup, nil
}

func checkEnvironment() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GOWORK=") && !strings.HasPrefix(e, "GOFLAGS=") && !strings.HasPrefix(e, "GOTOOLCHAIN=") {
			env = append(env, e)
		}
	}
	return append(env, "GOWORK=off", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=auto")
}

type cappedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (2 << 20) - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func runCheck(ctx context.Context, dir, name string, args ...string) CommandResult {
	result := CommandResult{Command: name + " " + strings.Join(args, " "), Status: "passed"}
	cmd := exec.CommandContext(ctx, name, args...)
	configureCheckProcess(cmd)
	cmd.Dir = dir
	cmd.Env = checkEnvironment()
	cmd.WaitDelay = time.Second
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result.Output = stdout.String() + stderr.String()
	result.Truncated = stdout.truncated || stderr.truncated
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	}
	if ctx.Err() != nil {
		result.Status = "unavailable"
		result.Error = ctx.Err().Error()
	}
	if len(args) > 0 && args[0] == "test" && result.Status == "passed" {
		packages := 0
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		for {
			var event struct{ Action, Test, Package string }
			err := decoder.Decode(&event)
			if err == io.EOF {
				break
			}
			if err != nil {
				result.Status = "unavailable"
				result.Error = "invalid or truncated go test JSON"
				break
			}
			if event.Package != "" {
				packages++
			}
			if event.Action == "pass" && event.Test != "" {
				result.TestsRun++
			}
		}
		if packages == 0 && result.Status == "passed" {
			result.Status = "unavailable"
			result.Error = "go test did not report any packages"
		}
	}
	return result
}

func buildAndTest(ctx context.Context, dir string) []CommandResult {
	steps := []CommandResult{runCheck(ctx, dir, "go", "build", "./...")}
	if steps[0].Status == "passed" {
		steps = append(steps, runCheck(ctx, dir, "go", "test", "-json", "-count=1", "./..."))
	}
	return steps
}
func stepsPassed(steps []CommandResult) bool {
	if len(steps) == 0 {
		return false
	}
	for _, s := range steps {
		if s.Status != "passed" {
			return false
		}
	}
	return true
}

func CheckUpgradeTrials(parent context.Context, modules []*Module, timeout time.Duration, workers int, logger *log.Logger) {
	group := new(errgroup.Group)
	group.SetLimit(max(1, workers))
	for _, m := range modules {
		group.Go(func() error {
			var candidates []*Dependency
			for i := range m.Requires {
				d := &m.Requires[i]
				if isUpdate(d.UpdateKind) && !d.Replaced {
					candidates = append(candidates, d)
				}
			}
			if len(candidates) == 0 {
				return nil
			}
			ctx, cancel := context.WithTimeout(parent, timeout)
			dir, cleanup, err := copyModule(ctx, m)
			if err == nil {
				logger.Printf("Checking baseline in copy of %s", m.Dir)
				m.Baseline = buildAndTest(ctx, dir)
			}
			cleanup()
			cancel()
			if err != nil || !stepsPassed(m.Baseline) {
				for _, d := range candidates {
					d.Trial = UpgradeTrial{Status: "blocked", Target: d.LatestVersion, Error: "baseline did not pass; upgrade not attempted"}
					if err != nil {
						d.Trial.Error = err.Error()
					}
				}
				return nil
			}
			for _, d := range candidates {
				d.Trial = UpgradeTrial{Target: d.LatestVersion, Status: "unavailable"}
				ctx, cancel := context.WithTimeout(parent, timeout)
				dir, cleanup, err := copyModule(ctx, m)
				if err != nil {
					d.Trial.Error = err.Error()
					cancel()
					continue
				}
				logger.Printf("Trying %s@%s in copy of %s", d.Path, d.LatestVersion, m.Dir)
				d.Trial.Steps = append(d.Trial.Steps, runCheck(ctx, dir, "go", "get", d.Path+"@"+d.LatestVersion))
				if stepsPassed(d.Trial.Steps) {
					d.Trial.Steps = append(d.Trial.Steps, buildAndTest(ctx, dir)...)
				}
				d.Trial.Status = "passed"
				for _, step := range d.Trial.Steps {
					if step.Status != "passed" {
						d.Trial.Status = step.Status
						d.Trial.Error = step.Error
						break
					}
				}
				cleanup()
				cancel()
			}
			return nil
		})
	}
	_ = group.Wait()
}

func checkLabel(s string) string {
	switch s {
	case "passed":
		return "Başarılı"
	case "failed":
		return "Başarısız"
	case "checked":
		return "Analiz tamamlandı"
	case "blocked":
		return "Deneme yapılamadı"
	case "unavailable":
		return "Sonuç alınamadı"
	default:
		return "Çalıştırılmadı"
	}
}

// Metadata commands may update go.mod/go.sum too, so verification modes resolve
// updates in a disposable copy before doing the baseline and candidate checks.
func CheckUpdatesInCopies(parent context.Context, modules []*Module, timeout time.Duration, workers int, logger *log.Logger) {
	group := new(errgroup.Group)
	group.SetLimit(max(1, workers))
	for _, m := range modules {
		group.Go(func() error {
			ctx, cancel := context.WithTimeout(parent, timeout)
			defer cancel()
			dir, cleanup, err := copyModule(ctx, m)
			defer cleanup()
			if err != nil {
				m.UpdateStatus = "unavailable"
				m.UpdateError = err.Error()
				return nil
			}
			clone := *m
			clone.Dir = dir
			clone.Requires = append([]Dependency(nil), m.Requires...)
			checkModule(ctx, &clone, timeout)
			m.Requires, m.UpdateStatus, m.UpdateError, m.UpdateCount = clone.Requires, clone.UpdateStatus, clone.UpdateError, clone.UpdateCount
			return nil
		})
	}
	_ = group.Wait()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
