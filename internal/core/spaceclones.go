package core

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Files that share their blocks (APFS clones), so a folder's size can be told from what deleting it gives back, and a
// sum over folders counts shared blocks once (luoke-scan#226). Nothing is read of a file: what is used comes with the
// walk's bulk read (Entry.Shares, CloneID), and one getattrlist for each file that shares blocks and is followed
// (shareFacts): the bytes of its own, how many whole clones there are of it.
//
// What the volume says, and what is made of it:
//   - Whole clones of each other (nobody changed any of them) have the same clone id, and each says how many they are
//     on the volume (measured or not). Those are a group: its blocks count once, and deleting gives them back only
//     when every one of the group goes.
//   - A clone that was changed since gets an id of its own; it only says "may share blocks", and how many bytes are
//     its own (ATTR_CMNEXT_PRIVATESIZE). Whom it shares the rest with is not known without reading its extents: those
//     are the loose ones. So are whole clones too small to follow one by one.
//   - A file that shares nothing is not kept here at all.
//
// Hard links (one file under several names; any volume, the count comes with every read: Entry.Links) are kept the
// same way, as each name's size is in the folder's:
//   - The names of a file of spaceCloneMin or more are a group by its inode (one lstat for each such name): its blocks
//     count once, and deleting gives them back only when every name goes.
//   - Smaller ones are not followed one by one (a conda environment is tens of thousands of them): each name counts as
//     its share of the file, the size divided by the number of names, and as given back by nothing. So does a file
//     that has several names and shares blocks as a clone too: it is counted as hard links only, not twice.

const (
	// spaceCloneMin: whole clones smaller than this are not followed as groups (a cloned tree of small files would be
	// a row each); they count as loose.
	spaceCloneMin = 1 << 20
	// spaceCloneGroups: how many groups a folder keeps at most, the biggest; the rest count as loose.
	spaceCloneGroups = 4096
)

// SpaceCloneGroup is what a folder holds of one group: whole clones of each other, or the names of one file.
type SpaceCloneGroup struct {
	Count int64 `json:"count"` // how many of the group are in the folder
	Bytes int64 `json:"bytes"` // their allocated sizes together, as the folder's size counts them
	Size  int64 `json:"size"`  // the allocated size of one: what the group takes on disk
	Refs  int64 `json:"refs"`  // how many the group has on the whole volume, as the volume says (0: it did not say)
}

// spaceLinkGroup marks, in SpaceClones.Groups, the id of a group that is one file's names: this, then its inode. A
// clone id is digits only.
const spaceLinkGroup = "i"

// SpaceClones is what a measured folder holds, all the way down, of files that share blocks. Unchecked: the bytes of
// subfolders found unchanged that had none remembered (measured by a version before this one): not looked at for
// sharing, counted as sharing nothing.
type SpaceClones struct {
	// Volume the folder is on (clone ids are a volume's own).
	Volume string                     `json:"volume,omitempty"`
	Groups map[string]SpaceCloneGroup `json:"groups,omitempty"` // by clone id, or spaceLinkGroup and the inode
	// The loose ones: their allocated sizes together, and how much of that is theirs alone.
	LooseBytes   int64 `json:"looseBytes,omitempty"`
	LoosePrivate int64 `json:"loosePrivate,omitempty"`
	// The names of files with several names that are not followed as groups: their allocated sizes together, and
	// each one's share of its file (its size divided by how many names the file has) together.
	LinkBytes int64 `json:"linkBytes,omitempty"`
	LinkOnce  int64 `json:"linkOnce,omitempty"`
	Unchecked int64 `json:"unchecked,omitempty"`
}

// SpaceClonesTable keeps SpaceClones by canonical path, for the folders SpaceMixTable keeps a mix of, as they were
// when last walked. A folder walked by this version has a row, also when nothing in it shares anything.
func SpaceClonesTable(s *Store) Table[SpaceClones] { return NewTable[SpaceClones](s, "clones", 1) }

// shareFacts are, of a file that shares blocks, the bytes only it holds (ATTR_CMNEXT_PRIVATESIZE) and how many files
// on the volume are whole clones of its data stream, itself counted (ATTR_CMNEXT_CLONE_REFCNT; 0 when the volume does
// not say); ok false when they cannot be read. One getattrlist, not following a link. A variable for the tests.
var shareFacts = func(path string) (own, refs int64, ok bool) {
	var buf [64]byte
	if getattrlist(path, attrs(unix.ATTR_CMN_RETURNED_ATTRS, attrCmnExtPrivateSize|attrCmnExtCloneRefcnt), buf[:],
		unix.FSOPT_ATTR_CMN_EXTENDED|unix.FSOPT_NOFOLLOW) != nil {
		return 0, 0, false
	}
	// u_int32_t length; attribute_set_t returned (common, vol, dir, file, fork); then the size (off_t), the count (u_int32_t).
	got := binary.LittleEndian.Uint32(buf[20:24])
	if got&attrCmnExtPrivateSize == 0 {
		return 0, 0, false
	}
	own = int64(binary.LittleEndian.Uint64(buf[24:32]))
	if got&attrCmnExtCloneRefcnt != 0 {
		refs = int64(binary.LittleEndian.Uint32(buf[32:36]))
	}
	return own, refs, true
}

// attrCmnExtCloneRefcnt is ATTR_CMNEXT_CLONE_REFCNT (<sys/attr.h>; x/sys does not name it).
const attrCmnExtCloneRefcnt = 0x00001000

// linkInode is the inode of a file that has several names; 0 when it cannot be read. A variable for the tests.
var linkInode = Inode

// linked counts one name of a file that has several.
func (c *SpaceClones) linked(e Entry) {
	// Shares blocks as a clone too (the "may share" flag stays on a file whose clones are all gone: its own bytes
	// tell): not a group, so it is never taken as given back, and its blocks are not counted against the clone's.
	shares := e.Shares == sharesAll
	if e.Shares == sharesSome {
		own, _, ok := shareFacts(e.Path)
		shares = ok && own < e.Bytes
	}
	if !shares && e.Bytes >= spaceCloneMin {
		if ino := linkInode(e.Path); ino != 0 {
			if c.Groups == nil {
				c.Groups = map[string]SpaceCloneGroup{}
			}
			id := spaceLinkGroup + strconv.FormatUint(ino, 10)
			g := c.Groups[id]
			g.Count++
			g.Bytes += e.Bytes
			g.Size = max(g.Size, e.Bytes)
			g.Refs = max(g.Refs, int64(e.Links))
			c.Groups[id] = g
			return
		}
	}
	c.LinkBytes += e.Bytes
	c.LinkOnce += e.Bytes / int64(e.Links)
}

// file counts one file as the walk's read gave it.
func (c *SpaceClones) file(e Entry) {
	if e.Bytes <= 0 {
		return
	}
	if e.Links > 1 {
		c.linked(e)
		return
	}
	if e.Shares == 0 {
		return
	}
	if e.Shares == sharesAll {
		if e.Bytes < spaceCloneMin {
			c.LooseBytes += e.Bytes // all of it shared, none its own
			return
		}
		own, refs, ok := shareFacts(e.Path)
		if ok && refs == 1 {
			// The only whole clone of its data stream: what it shares, it shares with a clone that was changed since
			// (grown, cut, partly rewritten). Loose, like that one.
			c.LooseBytes += e.Bytes
			c.LoosePrivate += min(max(own, 0), e.Bytes)
			return
		}
		if c.Groups == nil {
			c.Groups = map[string]SpaceCloneGroup{}
		}
		id := strconv.FormatUint(e.CloneID, 10)
		g := c.Groups[id]
		g.Count++
		g.Bytes += e.Bytes
		g.Size = max(g.Size, e.Bytes)
		g.Refs = max(g.Refs, refs)
		c.Groups[id] = g
		return
	}
	// May share: the flag stays on a file whose clones are all gone, so only its own bytes tell.
	own, _, ok := shareFacts(e.Path)
	if !ok || own >= e.Bytes {
		return
	}
	c.LooseBytes += e.Bytes
	c.LoosePrivate += max(own, 0)
}

// add counts a subfolder's (on the same volume).
func (c *SpaceClones) add(sub SpaceClones) {
	for id, g := range sub.Groups {
		if c.Groups == nil {
			c.Groups = map[string]SpaceCloneGroup{}
		}
		x := c.Groups[id]
		x.Count += g.Count
		x.Bytes += g.Bytes
		x.Size = max(x.Size, g.Size)
		x.Refs = max(x.Refs, g.Refs)
		c.Groups[id] = x
	}
	c.LooseBytes += sub.LooseBytes
	c.LoosePrivate += sub.LoosePrivate
	c.LinkBytes += sub.LinkBytes
	c.LinkOnce += sub.LinkOnce
	c.Unchecked += sub.Unchecked
	c.trim()
}

// trim keeps the spaceCloneGroups biggest groups; the others become loose (shared, none their own), a file's names
// what names not followed are (each its share of the file).
func (c *SpaceClones) trim() {
	if len(c.Groups) <= spaceCloneGroups {
		return
	}
	ids := make([]string, 0, len(c.Groups))
	for id := range c.Groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if a, b := c.Groups[ids[i]].Size, c.Groups[ids[j]].Size; a != b {
			return a > b
		}
		return ids[i] < ids[j]
	})
	for _, id := range ids[spaceCloneGroups:] {
		g := c.Groups[id]
		if strings.HasPrefix(id, spaceLinkGroup) {
			c.LinkBytes += g.Bytes
			c.LinkOnce += g.Bytes / max(g.Refs, 1)
		} else {
			c.LooseBytes += g.Bytes
		}
		delete(c.Groups, id)
	}
}

// SpaceCloneSum is what several measured folders hold together of files that share blocks (folders that do not
// contain one another).
type SpaceCloneSum struct {
	groups                   map[string]SpaceCloneGroup // by volume and the group's id
	looseBytes, loosePrivate int64
	linkBytes, linkOnce      int64
	// Unchecked: bytes not looked at for sharing (SpaceClones.Unchecked, and folders added without a record).
	Unchecked int64
}

// Add counts one folder's.
func (s *SpaceCloneSum) Add(c SpaceClones) {
	for id, g := range c.Groups {
		if s.groups == nil {
			s.groups = map[string]SpaceCloneGroup{}
		}
		k := c.Volume + "/" + id
		x := s.groups[k]
		x.Count += g.Count
		x.Bytes += g.Bytes
		x.Size = max(x.Size, g.Size)
		x.Refs = max(x.Refs, g.Refs)
		s.groups[k] = x
	}
	s.looseBytes += c.LooseBytes
	s.loosePrivate += c.LoosePrivate
	s.linkBytes += c.LinkBytes
	s.linkOnce += c.LinkOnce
	s.Unchecked += c.Unchecked
}

// Repeated is how many of the folders' bytes (their sizes added up) are blocks counted before: of a group, all but
// one; of the loose ones, half of what they share (right for two files sharing with each other, the common case; a
// file sharing with a group, or three with each other, is counted too high; one sharing with a file outside the
// folders too low); of a file's names not followed as a group, all but each one's share of the file (right when all
// its names are in the folders; with a name outside them too much is taken as repeated, by that name's share; a file
// with several names that is a clone too is not counted against its clones, too little).
func (s *SpaceCloneSum) Repeated() int64 {
	var out int64
	for _, g := range s.groups {
		out += g.Bytes - g.Size
	}
	return out + (s.looseBytes-s.loosePrivate)/2 + s.linkBytes - s.linkOnce
}

// Split says, of the folders' bytes, how many are repeats inside them (a group's second and later files) and how many
// are blocks deleting the folders would not give back (shared): a group with one of its files elsewhere, and what the
// loose ones share (with whom is not known: all of it counts as shared). Of a file's names not followed as a group,
// each one's share of the file is shared and the rest of it repeated (where the other names are is not known). The
// rest of the bytes is what deleting gives back. all: every measured folder's, these among them: a group is whole in
// these folders when they hold as many of it as the volume says there are, and as many as all the measured folders
// hold.
func (s *SpaceCloneSum) Split(all *SpaceCloneSum) (repeated, shared int64) {
	for k, g := range s.groups {
		repeated += g.Bytes - g.Size
		total := g.Refs
		if all != nil {
			total = max(total, all.groups[k].Count, all.groups[k].Refs)
		}
		if g.Count < total {
			shared += g.Size
		}
	}
	return repeated + s.linkBytes - s.linkOnce, shared + s.looseBytes - s.loosePrivate + s.linkOnce
}
