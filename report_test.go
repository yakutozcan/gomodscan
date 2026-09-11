package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportAnalysisAndEscaping(t *testing.T) {
	scan := Scan(context.Background(), []string{"testdata/tree"}, ScanOptions{Exclude: []string{"vendor"}}, log.New(io.Discard, "", 0))
	report := BuildReport(scan, false)
	if report.UniqueDependencies != 2 || len(report.Conflicts) != 1 || len(report.GoVersions) != 3 || len(report.Errors) != 1 {
		t.Fatalf("analysis: %+v", report)
	}
	report.Roots = []string{`<script>alert("x")</script>`}
	var out bytes.Buffer
	if err := RenderReport(&out, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), report.Roots[0]) || !strings.Contains(out.String(), "&lt;script&gt;") {
		t.Fatal("unsafe HTML output")
	}
	if strings.Contains(out.String(), "ZgotmplZ") {
		t.Fatal("invalid template style value")
	}
}

func TestCLI(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.html")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"-o", output, "testdata/tree"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || !bytes.Contains(data, []byte("example.com/nested")) {
		t.Fatalf("output: %v", err)
	}
	for _, args := range [][]string{nil, {"-depth", "-1", "."}, {"-timeout", "0s", "."}, {"-scan-workers", "0", "."}, {"-verify-workers", "0", "."}, {"-verify-timeout", "0s", "."}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted invalid args: %v", args)
		}
	}
}
