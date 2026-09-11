package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"time"

	"golang.org/x/sync/errgroup"
)

type ReachabilityResult struct {
	Status         string                `json:"status"`
	Error          string                `json:"error,omitempty"`
	ScannerVersion string                `json:"scanner_version,omitempty"`
	Findings       []ReachabilityFinding `json:"findings"`
}
type ReachabilityFinding struct {
	ID           string      `json:"osv"`
	FixedVersion string      `json:"fixed_version,omitempty"`
	Trace        []CallFrame `json:"trace"`
}
type CallFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Receiver string `json:"receiver,omitempty"`
}
type VulnConfig struct {
	Protocol       string `json:"protocol_version"`
	ScannerVersion string `json:"scanner_version"`
	ScanLevel      string `json:"scan_level"`
	ScanMode       string `json:"scan_mode"`
}

func DecodeReachability(reader io.Reader) (ReachabilityResult, error) {
	result := ReachabilityResult{Status: "checked"}
	decoder := json.NewDecoder(reader)
	configSeen := false
	for {
		var msg struct {
			Config  *VulnConfig          `json:"config"`
			Finding *ReachabilityFinding `json:"finding"`
		}
		err := decoder.Decode(&msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, fmt.Errorf("decode govulncheck JSON: %w", err)
		}
		if !configSeen {
			if msg.Config == nil || msg.Config.Protocol != "v1.0.0" || msg.Config.ScanLevel != "symbol" || msg.Config.ScanMode != "source" {
				return result, fmt.Errorf("unsupported or missing govulncheck source/symbol configuration")
			}
			configSeen = true
			result.ScannerVersion = msg.Config.ScannerVersion
		}
		if msg.Finding != nil {
			if msg.Finding.ID == "" || len(msg.Finding.Trace) == 0 {
				return result, fmt.Errorf("invalid govulncheck finding")
			}
			// Module/package-only findings do not prove a call to a vulnerable function.
			if msg.Finding.Trace[0].Function != "" {
				result.Findings = append(result.Findings, *msg.Finding)
			}
		}
	}
	if !configSeen {
		return result, fmt.Errorf("empty govulncheck output")
	}
	return result, nil
}

func CheckReachability(parent context.Context, modules []*Module, timeout time.Duration, workers int, logger *log.Logger) {
	binary, lookupErr := exec.LookPath("govulncheck")
	group := new(errgroup.Group)
	group.SetLimit(max(1, workers))
	for _, m := range modules {
		group.Go(func() error {
			m.Reachability.Status = "unavailable"
			if lookupErr != nil {
				m.Reachability.Error = "govulncheck is not installed or not on PATH"
				return nil
			}
			ctx, cancel := context.WithTimeout(parent, timeout)
			defer cancel()
			dir, cleanup, err := copyModule(ctx, m)
			defer cleanup()
			if err != nil {
				m.Reachability.Error = err.Error()
				return nil
			}
			logger.Printf("Analyzing reachable vulnerabilities in copy of %s", m.Dir)
			cmd := exec.CommandContext(ctx, binary, "-json", "-scan=symbol", "./...")
			configureCheckProcess(cmd)
			cmd.Dir = dir
			cmd.Env = checkEnvironment()
			cmd.WaitDelay = time.Second
			var stderr cappedBuffer
			cmd.Stderr = &stderr
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				m.Reachability.Error = err.Error()
				return nil
			}
			if err = cmd.Start(); err != nil {
				m.Reachability.Error = err.Error()
				return nil
			}
			result, decodeErr := DecodeReachability(pipe)
			if decodeErr != nil {
				cancel()
			}
			waitErr := cmd.Wait()
			if decodeErr != nil {
				err = decodeErr
			} else {
				err = waitErr
			}
			if err != nil {
				m.Reachability.Error = fmt.Sprintf("govulncheck failed: %v; %s", err, stderr.String())
				return nil
			}
			m.Reachability = result
			return nil
		})
	}
	_ = group.Wait()
}
