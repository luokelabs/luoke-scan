package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// A fake freshclam that behaves as ClamAV 1.5's on a Mac without Homebrew's ClamAV (luoke-scan#103): it downloads,
// then tests what it downloaded with the certificate folder from CVD_CERTS_DIR only (not --cvdcertsdir), and fails
// with 8 when that is not the folder holding the certificate.
const freshclamTestsWithEnv = `#!/bin/sh
dir=""; certs=""
for a in "$@"; do case "$a" in --datadir=*) dir="${a#--datadir=}";; --cvdcertsdir=*) certs="${a#--cvdcertsdir=}";; esac; done
echo "daily 27000" > "$dir/daily.cvd"; echo "main 62" > "$dir/main.cvd"
echo "$certs|$CVD_CERTS_DIR" > "$(dirname "$0")/seen"
if [ -z "$CVD_CERTS_DIR" ] || [ ! -f "$CVD_CERTS_DIR/clamav.crt" ]; then
  echo "ERROR: Failed to load new database: Broken or not a CVD file"; echo "ERROR: Database test FAILED."; exit 8
fi
exit 0
`

const sigtoolAnswersVersion = `#!/bin/sh
for a in "$@"; do case "$a" in --cvdcertsdir=*) [ "$CVD_CERTS_DIR" = "${a#--cvdcertsdir=}" ] || exit 9;; esac; done
echo "Version: 27000"
`

func TestUpdateGivesFreshclamsSelfTestTheCarriedCertificate(t *testing.T) {
	root := t.TempDir()
	tools := filepath.Join(root, "tools")
	os.MkdirAll(tools, 0o700)
	write := func(name, body string) string {
		p := filepath.Join(tools, name)
		if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	freshclam, sigtool := write("freshclam", freshclamTestsWithEnv), write("sigtool", sigtoolAnswersVersion)
	pem := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	was := ClamAVCerts
	defer func() { ClamAVCerts = was }()
	ClamAVCerts = func() ([]string, func()) { // as the packed build: the certificate it carries, in a folder of its own
		return clamAVCertsFrom(fstest.MapFS{"packaging/clamav-certs/clamav.crt": {Data: []byte(pem)}})
	}
	s, err := OpenStore(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	db := NewVirusDB(s, Tools{Freshclam: freshclam, Sigtool: sigtool})
	o := db.Update(s, time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC), true, time.Minute)
	if o.Kind != "updated" {
		t.Fatalf("update: %+v", o)
	}
	seen, _ := os.ReadFile(filepath.Join(tools, "seen"))
	parts := strings.SplitN(strings.TrimSpace(string(seen)), "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[0] != parts[1] {
		t.Errorf("--cvdcertsdir and CVD_CERTS_DIR must be the same folder: %q", seen)
	}
	if len(db.Files()) != 2 {
		t.Errorf("database files: %v", db.Files())
	}
}

func TestCertsEnv(t *testing.T) {
	if CertsEnv(nil, nil) != nil {
		t.Error("no certificate: the tool keeps this process's environment (nil)")
	}
	base := map[string]string{"LD_LIBRARY_PATH": "/x"}
	got := CertsEnv([]string{"--cvdcertsdir=/c"}, base)
	if got["CVD_CERTS_DIR"] != "/c" || got["LD_LIBRARY_PATH"] != "/x" {
		t.Errorf("with a base: %v", got)
	}
	if _, changed := base["CVD_CERTS_DIR"]; changed {
		t.Error("the base is not changed")
	}
	t.Setenv("LUOKE_SCAN_CERTS_TEST", "1")
	if got := CertsEnv([]string{"--cvdcertsdir=/c"}, nil); got["LUOKE_SCAN_CERTS_TEST"] != "1" || got["CVD_CERTS_DIR"] != "/c" {
		t.Errorf("without a base: this process's environment and the folder: %v", got)
	}
}
