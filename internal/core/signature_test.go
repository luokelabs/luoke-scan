package core

import (
	"os"
	"path/filepath"
	"testing"
)

// The one-run checks answer what checking one requirement at a time answers, on real signatures: Apple's program and
// app, an ad hoc one (this test binary, signed by the linker), one with its signature removed, one changed after signing.
func TestSignatureChecksMatchTheLongWay(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	adhoc := filepath.Join(dir, "adhoc")
	if err := os.WriteFile(adhoc, data, 0o700); err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(dir, "unsigned")
	if err := os.WriteFile(unsigned, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if r := Run(codesign, []string{"--remove-signature", unsigned}, RunOpts{}); r.Status != 0 {
		t.Fatalf("remove signature: %d %s", r.Status, r.Stderr)
	}
	changed := filepath.Join(dir, "changed")
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)/2] ^= 0xFF // a page the code directory hashes
	if err := os.WriteFile(changed, tampered, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]SigKind{"/usr/bin/true": SigApple, adhoc: SigAdhoc, unsigned: SigUnsigned, changed: SigInvalid,
		"/System/Applications/Calculator.app/Contents/MacOS/Calculator": SigApple}
	for p, want := range cases {
		fast, slow := SignatureOf(p), signatureSlow(SignatureSubject(p))
		if fast != slow || fast.Kind != want {
			t.Errorf("%s: SignatureOf %+v, the long way %+v, want kind %d", p, fast, slow, want)
		}
	}
	apps := map[string]TrustKind{"/System/Applications/Calculator.app": TrustApple, adhoc: TrustAdhoc, unsigned: TrustUnsigned,
		changed: TrustInvalid}
	for a, want := range apps {
		fast, slow := AppTrustOf(a), appTrustSlow(a)
		if fast != slow || fast.Kind != want {
			t.Errorf("%s: AppTrustOf %+v, the long way %+v, want kind %d", a, fast, slow, want)
		}
	}
}
