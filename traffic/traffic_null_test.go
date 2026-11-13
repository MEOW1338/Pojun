package traffic

import (
	"context"
	"strings"
	"testing"
)

// SQLite schema allows NULL in metadata columns (legacy/partial writers). Scanning
// those rows into plain strings/ints must not fail.
func TestMetadataQueriesHandleNullColumns(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts) VALUES('null-row',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Search("", 0, 10); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if hosts, err := tr.Hosts(); err != nil || len(hosts) == 0 {
		t.Fatalf("Hosts: %+v err=%v", hosts, err)
	}
	err = tr.ReadEvidence(context.Background(), []string{"null-row"}, func(EvidenceExchange) error { return nil })
	if err != nil && strings.Contains(err.Error(), "converting NULL") {
		t.Fatalf("ReadEvidence scanned NULL: %v", err)
	}
	if _, _, err := tr.Page(PageQuery{}, 0, 10); err != nil {
		t.Fatalf("Page: %v", err)
	}
	if _, _, err := tr.Get("null-row"); err != nil && !strings.Contains(err.Error(), "无正文记录") {
		t.Fatalf("Get: %v", err)
	}
}
