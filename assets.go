// Package assets is what luoke-scan carries inside its own program, so that the signature luoke's main app checks
// before starting it covers them too, wherever the program is: the generate tasks' prompts, freshclam's settings and,
// in a packed build, ClamAV's root certificate (copied into packaging/clamav-certs by scripts/package_app.py before it
// builds; only the README is in git).
package assets

import "embed"

//go:embed prompts/* packaging/freshclam.conf packaging/clamav-certs
var FS embed.FS
