package service

import ()

// What is not ported yet (each moves to a file of its own when it is).

type redraw struct {
	body  func(*Card)
	waits bool
}

const (
	homebrewRule      = "leftover.intel-homebrew"
	homebrewLinksRule = "leftover.intel-homebrew-links"
)
