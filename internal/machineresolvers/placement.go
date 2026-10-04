// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// The SecretPlacement.rule values.
const (
	ruleRequested        = "REQUESTED"
	rulePersonalDefault  = "PERSONAL_DEFAULT"
	ruleKeptByCaller     = "KEPT_BY_CALLER"
	ruleAlreadyPersonal  = "ALREADY_PERSONAL"
	ruleNoPersonalFolder = "NO_PERSONAL_FOLDER"
)

// accountKeyWords mark a field that names an account; secretKeyWords rule a
// field out even then, so a password equal to the caller's username never
// moves anything.
var (
	accountKeyWords = []string{"user", "login", "mail", "account"}
	secretKeyWords  = []string{"pass", "secret", "token", "key", "pin"}
)

func namesAnAccount(key string) bool {
	k := strings.ToLower(key)
	has := func(w string) bool { return strings.Contains(k, w) }
	return !slices.ContainsFunc(secretKeyWords, has) && slices.ContainsFunc(accountKeyWords, has)
}

// callerMatch is which part of a new secret names its caller, and by what.
// It carries field keys and the kind of identity, never a value.
type callerMatch struct {
	part     string // "name", or "<key> field"
	identity string // "email" or "username"
}

func (m callerMatch) String() string {
	return "the secret's " + m.part + " matches your " + m.identity
}

// matchCaller checks the name, then each account field in key order, for the
// caller's email or username as a whole word.
func matchCaller(username, email, name string, fields map[string]string) (callerMatch, bool) {
	check := func(part, value string) (callerMatch, bool) {
		switch {
		case hasWord(value, email):
			return callerMatch{part: part, identity: "email"}, true
		case hasWord(value, username):
			return callerMatch{part: part, identity: "username"}, true
		}
		return callerMatch{}, false
	}
	if m, ok := check("name", name); ok {
		return m, true
	}
	var keys []string
	for k := range fields {
		if namesAnAccount(k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		if m, ok := check(k+" field", fields[k]); ok {
			return m, true
		}
	}
	return callerMatch{}, false
}

// hasWord reports whether word occurs in text, ignoring case, with no word
// character touching either end. Letters, digits and "_" are word characters,
// and so is a dot between two of them, so "ada" is a word in "for ada." and
// "CORP\ada" but not in "adam" or "ada.smith".
func hasWord(text, word string) bool {
	if strings.TrimSpace(word) == "" {
		return false
	}
	t, w := strings.ToLower(text), strings.ToLower(word)
	for at := 0; at < len(t); {
		i := strings.Index(t[at:], w)
		if i < 0 {
			return false
		}
		start, end := at+i, at+i+len(w)
		if !joinsBefore(t, start) && !joinsAfter(t, end) {
			return true
		}
		_, size := utf8.DecodeRuneInString(t[start:])
		at = start + size
	}
	return false
}

func wordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

// joinsAfter reports whether the text from i continues a word.
func joinsAfter(t string, i int) bool {
	if i >= len(t) {
		return false
	}
	r, size := utf8.DecodeRuneInString(t[i:])
	if r == '.' {
		if i+size >= len(t) {
			return false
		}
		next, _ := utf8.DecodeRuneInString(t[i+size:])
		return wordRune(next)
	}
	return wordRune(r)
}

// joinsBefore reports whether the text up to i ends inside a word.
func joinsBefore(t string, i int) bool {
	if i <= 0 {
		return false
	}
	r, size := utf8.DecodeLastRuneInString(t[:i])
	if r == '.' {
		if i-size <= 0 {
			return false
		}
		prev, _ := utf8.DecodeLastRuneInString(t[:i-size])
		return wordRune(prev)
	}
	return wordRune(r)
}

// personalTree finds the caller's Personal folder (a personal folder whose
// parent isn't one of theirs: the master root is hidden from every token) and
// whether requested is in their personal tree. A token only ever lists its own
// owner's personal folders.
func personalTree(folders []*vaultv1.Folder, requested string) (root string, requestedPersonal bool) {
	personal := map[string]bool{}
	for _, f := range folders {
		if f.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL {
			personal[f.GetId()] = true
		}
	}
	for _, f := range folders {
		if personal[f.GetId()] && !personal[f.GetParentId()] {
			root = f.GetId()
			break
		}
	}
	return root, personal[requested]
}

// placeSecret picks the folder a principal's new secret goes to. A personal
// token's secret that names its owner belongs in the owner's Personal folder:
// once it's in a shared folder, no token can move it back (a move into a
// personal folder needs a site admin).
func (r *mutationResolver) placeSecret(ctx context.Context, requested, name string, fields map[string]string, keep bool) (*SecretPlacement, error) {
	lg := r.logger().Ctx(ctx)
	p := &SecretPlacement{FolderID: requested, RequestedFolderID: requested}
	username, email := resolvers.CallerIdentity(ctx)
	m, ok := matchCaller(username, email, name, fields)
	if !ok {
		p.Rule, p.Reason = ruleRequested, "stored in the requested folder: nothing in the secret names you"
		lg.Debug("secret placement", log.F("actor", resolvers.CallerID(ctx)), log.F("rule", p.Rule), log.F("folder", requested))
		return p, nil
	}
	if keep {
		p.Rule, p.Reason = ruleKeptByCaller, m.String()+", but keepFolder: true kept the requested folder"
	} else {
		list, err := r.Vault.ListFoldersForPrincipal(ctx, &vaultv1.ListFoldersForPrincipalRequest{Actor: resolvers.MachineActorOf(ctx)})
		if err != nil {
			lg.Warn("secret placement: folder listing failed", log.F("actor", resolvers.CallerID(ctx)), log.F("error", err.Error()))
			return nil, err
		}
		root, requestedPersonal := personalTree(list.GetFolders(), requested)
		switch {
		case requestedPersonal:
			p.Rule, p.Reason = ruleAlreadyPersonal, m.String()+", and the requested folder is already personal"
		case root == "":
			p.Rule, p.Reason = ruleNoPersonalFolder, m.String()+", but you have no Personal folder yet, so it was stored in the requested folder"
		default:
			p.FolderID = root
			p.Rule, p.Reason = rulePersonalDefault, m.String()+", so it was stored in your Personal folder; pass keepFolder: true to keep the requested folder"
		}
	}
	lg.Info("secret placement", log.F("actor", resolvers.CallerID(ctx)), log.F("rule", p.Rule), log.F("matched", m.part),
		log.F("identity", m.identity), log.F("requested_folder", requested), log.F("folder", p.FolderID))
	return p, nil
}
