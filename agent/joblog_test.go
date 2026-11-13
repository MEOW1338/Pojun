package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 日志读取必须有界：offset=0 读尾部、offset>0 读窗口，总行数仍然准确。
func TestReadJobLogTailAndWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.log")
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "line-%d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	tail, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 || len(tail) != 10 {
		t.Fatalf("total=%d window=%d，应为 1000/10", total, len(tail))
	}
	if tail[0] != "line-990" || tail[9] != "line-999" {
		t.Fatalf("尾部窗口不对：首 %q 末 %q", tail[0], tail[9])
	}

	win, total, err := readJobLog(path, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 || len(win) != 3 {
		t.Fatalf("total=%d window=%d，应为 1000/3", total, len(win))
	}
	if win[0] != "line-5" || win[2] != "line-7" {
		t.Fatalf("偏移窗口不对：%v", win)
	}

	// 偏移越界：空窗口，不报错。
	empty, total, err := readJobLog(path, 5000, 10)
	if err != nil || len(empty) != 0 || total != 1000 {
		t.Fatalf("越界偏移应返回空窗口：window=%d total=%d err=%v", len(empty), total, err)
	}
}

// 超长单行不能整行读入内存：截断并标记，行号不因此错位。
func TestReadJobLogTruncatesHugeLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.log")
	huge := strings.Repeat("A", jobLogLineMax*4)
	if err := os.WriteFile(path, []byte(huge+"\nshort\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(lines) != 2 {
		t.Fatalf("total=%d lines=%d，应为 2/2", total, len(lines))
	}
	if len(lines[0]) > jobLogLineMax+len(" …(行超长已截断)") {
		t.Fatalf("超长行未被截断：%d 字节", len(lines[0]))
	}
	if !strings.Contains(lines[0], "已截断") {
		t.Fatal("超长行应带截断标记")
	}
	if lines[1] != "short" {
		t.Fatalf("截断不应影响后续行：%q", lines[1])
	}
}

func TestReadJobLogEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	lines, total, err := readJobLog(path, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(lines) != 0 {
		t.Fatalf("空文件应返回 0 行：total=%d lines=%d", total, len(lines))
	}
}
