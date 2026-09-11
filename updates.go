package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
)

type ListedModule struct {
	GoVersion  string        `json:"GoVersion,omitempty"`
	Time       *time.Time    `json:"Time,omitempty"`
	Deprecated string        `json:"Deprecated,omitempty"`
	Retracted  []string      `json:"Retracted,omitempty"`
	Path       string        `json:"Path"`
	Version    string        `json:"Version"`
	Update     *ListedModule `json:"Update,omitempty"`
	Replace    *ListedModule `json:"Replace,omitempty"`
	Error      *ModuleError  `json:"Error,omitempty"`
}
type ModuleError struct {
	Err string `json:"Err"`
}

func DecodeModules(reader io.Reader) (map[string]ListedModule, error) {
	result := map[string]ListedModule{}
	decoder := json.NewDecoder(reader)
	for {
		var m ListedModule
		err := decoder.Decode(&m)
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if m.Error != nil {
			return nil, fmt.Errorf("module %s: %s", m.Path, m.Error.Err)
		}
		if m.Replace != nil && m.Replace.Error != nil {
			return nil, fmt.Errorf("replacement %s: %s", m.Replace.Path, m.Replace.Error.Err)
		}
		result[m.Path] = m
	}
}

func CheckUpdates(ctx context.Context, modules []*Module, timeout time.Duration, logger *log.Logger) {
	group, ctx := errgroup.WithContext(ctx)
	semaphore := make(chan struct{}, runtime.NumCPU())
	for _, m := range modules {
		group.Go(func() error {
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				m.UpdateStatus = "unavailable"
				m.UpdateError = ctx.Err().Error()
				return nil
			}
			defer func() { <-semaphore }()
			if m.Error != "" {
				m.UpdateStatus = "unavailable"
				m.UpdateError = "cannot check updates: invalid module"
				return nil
			}
			logger.Printf("Checking updates in %s", m.Dir)
			checkModule(ctx, m, timeout)
			if m.UpdateError != "" {
				logger.Printf("Update check failed for %s: %s", m.Dir, m.UpdateError)
			}
			return nil
		})
	}
	_ = group.Wait()
}

func checkModule(parent context.Context, m *Module, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	listed, err := runGoList(ctx, m.Dir, "-u", "-retracted", "all")
	if err != nil {
		m.UpdateStatus = "unavailable"
		m.UpdateError = err.Error()
		return
	}
	m.UpdateStatus = "available"
	for i := range m.Requires {
		d := &m.Requires[i]
		found, ok := listed[d.Path]
		if !ok {
			d.UpdateKind = "unknown"
			continue
		}
		d.ResolvedVersion = found.Version
		d.Deprecated, d.Retracted = found.Deprecated, found.Retracted
		if found.Replace != nil {
			d.Replaced = true
			d.UpdateKind = "replaced"
			continue
		}
		// Explicit @latest obtains the preferred release and its Go requirement,
		// including when the current version is already up to date.
		latest, latestErr := runGoList(ctx, m.Dir, d.Path+"@latest")
		target, exists := latest[d.Path]
		if latestErr != nil || !exists || !semver.IsValid(target.Version) {
			d.MetadataError = "latest metadata unavailable"
			if latestErr != nil {
				d.MetadataError += ": " + latestErr.Error()
			}
			d.UpdateKind = "unknown"
			continue
		}
		d.LatestVersion, d.LatestGoVersion, d.LatestTime = target.Version, target.GoVersion, target.Time
		if target.Deprecated != "" {
			d.Deprecated = target.Deprecated
		}
		d.UpdateKind = UpdateKind(d.Version, d.LatestVersion)
		if isUpdate(d.UpdateKind) {
			d.UpdateVersion = d.LatestVersion
			m.UpdateCount++
		}

	}
}

func UpdateKind(current, next string) string {
	if !semver.IsValid(current) || !semver.IsValid(next) {
		return "unknown"
	}
	if semver.Compare(next, current) <= 0 {
		return "current"
	}
	if semver.Major(current) != semver.Major(next) {
		return "major"
	}
	if semver.MajorMinor(current) != semver.MajorMinor(next) {
		return "minor"
	}
	return "patch"
}

// runGoList decodes the stdout stream and always reaps the command, including
// decoder errors. A child context prevents a bad response cancelling siblings.
func runGoList(parent context.Context, dir string, args ...string) (map[string]ListedModule, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	commandArgs := append([]string{"list", "-m", "-json"}, args...)
	cmd := exec.CommandContext(ctx, "go", commandArgs...)
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GOFLAGS=") && !strings.HasPrefix(variable, "GOTOOLCHAIN=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "GOFLAGS=-mod=mod", "GOTOOLCHAIN=auto")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	listed, decodeErr := DecodeModules(pipe)
	if decodeErr != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if decodeErr != nil {
		err = decodeErr
	} else {
		err = waitErr
	}
	if parent.Err() != nil {
		err = parent.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("go list failed: %w; %s", err, strings.TrimSpace(stderr.String()))
	}
	return listed, nil
}

func isUpdate(kind string) bool { return kind == "major" || kind == "minor" || kind == "patch" }
