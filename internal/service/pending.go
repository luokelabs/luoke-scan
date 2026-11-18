package service

import ()

// What is not ported yet (each moves to a file of its own when it is).

// redraw: the round's card as it is now, for a tool answering a click on it (roundRedraw).
type redraw struct {
	body  func(*Card) // under an answer: a divider, then the card
	card  func(*Card) // the card alone, in place of an answer
	waits bool        // something on it still waits for the user
	rest  int         // how many things it sends to the scan page (roundRest)
	data  O           // the card as data (roundData), for a core that draws it itself (top-level ADR 0028)
}

const (
	homebrewRule      = "leftover.intel-homebrew"
	homebrewLinksRule = "leftover.intel-homebrew-links"
)
