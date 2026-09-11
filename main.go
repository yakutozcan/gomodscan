package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gomodscan:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("gomodscan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("o", "gomod-report.html", "Output HTML file")
	vulns := flags.Bool("check-vulns", false, "Query OSV vulnerabilities (enabled with -check-updates; =false disables)")
	minimumAge := flags.Duration("minimum-release-age", 72*time.Hour, "Warn about releases younger than this duration")
	reachability := flags.Bool("govulncheck", false, "Analyze reachable vulnerabilities with installed govulncheck")
	trials := flags.Bool("try-upgrades", false, "Run builds and tests in temporary module copies (executes project tests)")
	verifyTimeout := flags.Duration("verify-timeout", 5*time.Minute, "Timeout per baseline, upgrade trial or govulncheck module")
	verifyWorkers := flags.Int("verify-workers", 2, "Concurrent verification modules")
	updates := flags.Bool("check-updates", false, "Check dependency updates")
	excluded := flags.String("exclude", "vendor,node_modules,.git,testdata", "Comma-separated directory names to skip")
	depth := flags.Int("depth", 0, "Maximum directory depth (0 = unlimited)")
	timeout := flags.Duration("timeout", 60*time.Second, "Command timeout per module")
	scanWorkers := flags.Int("scan-workers", runtime.NumCPU(), "Maximum concurrent module parsing and Git workers")
	verbose := flags.Bool("v", false, "Write detailed logs to stderr")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: gomodscan [flags] <directory> [directory...]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if flags.NArg() == 0 {
		flags.Usage()
		return fmt.Errorf("at least one directory is required")
	}
	if *depth < 0 || *timeout <= 0 || *minimumAge < 0 || *scanWorkers < 1 || *verifyTimeout <= 0 || *verifyWorkers < 1 {
		return fmt.Errorf("depth and minimum-release-age must be non-negative and timeouts and worker counts must be positive")
	}
	if *trials {
		*updates = true
	}
	logger := log.New(io.Discard, "", log.LstdFlags)
	if *verbose {
		logger.SetOutput(stderr)
	}
	result := Scan(ctx, flags.Args(), ScanOptions{Exclude: strings.Split(*excluded, ","), Depth: *depth, Timeout: *timeout, Workers: *scanWorkers}, logger)
	if *updates {
		if *trials || *reachability {
			CheckUpdatesInCopies(ctx, result.Modules, *timeout, *verifyWorkers, logger)
		} else {
			CheckUpdates(ctx, result.Modules, *timeout, logger)
		}
	}
	checkVulns := *updates || *vulns
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "check-vulns" {
			checkVulns = *vulns
		}
	})
	if checkVulns {
		CheckSecurity(ctx, result.Modules, *timeout, logger)
	}
	AssessDependencies(result.Modules, *minimumAge, time.Now())
	if *reachability {
		CheckReachability(ctx, result.Modules, *verifyTimeout, *verifyWorkers, logger)
	}
	if *trials {
		CheckUpgradeTrials(ctx, result.Modules, *verifyTimeout, *verifyWorkers, logger)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	report := BuildReport(result, *updates)
	report.CheckedVulnerabilities = checkVulns
	if err := WriteReport(*output, report); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Report written to %s (%d modules, %d errors)\n", *output, len(report.Modules), len(report.Errors))
	return nil
}
