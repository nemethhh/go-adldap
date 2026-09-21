package adtest

import (
	"strings"

	"github.com/jimlambrt/gldap"
)

// handleBind accepts the one seeded principal and rejects everything else, so
// a test that means to exercise a failing bind gets one.
func (s *Server) handleBind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	if equalFoldDN(m.UserName, bindDN) && string(m.Password) == bindPassword {
		resp = r.NewBindResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	}
}

// rootDSE is what a base-scoped search on the empty DN returns. adldap.New
// reads defaultNamingContext from here to pin the domain.
func (s *Server) rootDSE() map[string][][]byte {
	return map[string][][]byte{
		"defaultNamingContext": {[]byte(DNC)},
		"dnsHostName":          {[]byte("dc01.corp.local")},
		"schemaNamingContext":  {[]byte("CN=Schema,CN=Configuration," + DNC)},
		"supportedLDAPVersion": {[]byte("3")},
	}
}

func (s *Server) handleSearch(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultOperationsError))
	defer func() { _ = w.Write(done) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		return
	}

	if m.BaseDN == "" && m.Scope == gldap.BaseObject {
		entry := r.NewSearchResponseEntry("")
		addAttrs(entry, s.rootDSE(), m.Attributes)
		_ = w.Write(entry)
		done = r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
		return
	}

	showDeleted := hasGldapControl(m.Controls, showDeletedOID)

	s.mu.Lock()
	type hit struct {
		dn    string
		attrs map[string][][]byte
	}
	var hits []hit
	for dn, attrs := range s.entries {
		if !inScope(dn, m.BaseDN, m.Scope) {
			continue
		}
		if isTombstone(attrs) && !showDeleted {
			continue
		}
		if !matchFilter(m.Filter, attrs) {
			continue
		}
		hits = append(hits, hit{dn: dn, attrs: attrs})
	}
	s.mu.Unlock()

	if len(hits) == 0 && !s.exists(m.BaseDN) && m.Scope == gldap.BaseObject {
		done = r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject))
		return
	}

	// SizeLimit is honoured exactly as a DC honours it: the server stops and
	// says so, rather than quietly returning a short answer.
	if m.SizeLimit > 0 && int64(len(hits)) > m.SizeLimit {
		hits = hits[:m.SizeLimit]
		for _, h := range hits {
			entry := r.NewSearchResponseEntry(h.dn)
			addAttrs(entry, h.attrs, m.Attributes)
			_ = w.Write(entry)
		}
		done = r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSizeLimitExceeded))
		return
	}

	for _, h := range hits {
		entry := r.NewSearchResponseEntry(h.dn)
		addAttrs(entry, h.attrs, m.Attributes)
		_ = w.Write(entry)
	}
	done = r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
}

func (s *Server) exists(dn string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for have := range s.entries {
		if equalFoldDN(have, dn) {
			return true
		}
	}
	return false
}

func inScope(dn, base string, scope gldap.Scope) bool {
	switch scope {
	case gldap.BaseObject:
		return equalFoldDN(dn, base)
	case gldap.SingleLevel:
		return isChildOf(dn, base)
	default:
		return isUnder(dn, base)
	}
}

// addAttrs writes the requested attributes onto a response entry. An empty
// request means "all", which is what AD does.
//
// Values cross as strings because that is gldap's API; a Go string is an
// arbitrary byte sequence, so a binary objectGUID survives intact.
func addAttrs(e *gldap.SearchResponseEntry, attrs map[string][][]byte, requested []string) {
	want := func(name string) bool {
		if len(requested) == 0 {
			return true
		}
		for _, r := range requested {
			if strings.EqualFold(r, name) || r == "*" {
				return true
			}
		}
		return false
	}
	for name, vals := range attrs {
		if !want(name) {
			continue
		}
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			out = append(out, string(v))
		}
		e.AddAttribute(name, out)
	}
}

// matchFilter is a deliberately minimal RFC 4515 subset: enough to exercise
// the encoding this module actually emits, not a filter engine. It handles
// (objectClass=*), (attr=value), (attr=*) and a conjunction of those.
func matchFilter(filter string, attrs map[string][][]byte) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	if strings.HasPrefix(filter, "(&") {
		for _, term := range splitTerms(filter[2 : len(filter)-1]) {
			if !matchFilter(term, attrs) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(filter, "(|") {
		for _, term := range splitTerms(filter[2 : len(filter)-1]) {
			if matchFilter(term, attrs) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(filter, "(!") {
		return !matchFilter(filter[2:len(filter)-1], attrs)
	}
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return false
	}
	body := filter[1 : len(filter)-1]
	// An extensible match, "attr:<rule-oid>:=value". The harness treats the
	// chain rule as a direct comparison, which is enough to tell the right
	// attribute from the wrong one — the distinction the filter turns on.
	if j := strings.Index(body, ":"); j > 0 && strings.Contains(body, ":=") {
		body = body[:j] + body[strings.Index(body, ":=")+1:]
	}
	i := strings.Index(body, "=")
	if i < 0 {
		return false
	}
	attr, want := body[:i], body[i+1:]
	vals, ok := lookupFold(attrs, attr)
	if !ok {
		return false
	}
	if want == "*" {
		return len(vals) > 0
	}
	unescaped := unescapeFilterValue(want)
	for _, v := range vals {
		if matchValue(string(v), unescaped) {
			return true
		}
	}
	return false
}

// matchValue compares one attribute value against an assertion, honouring the
// substring form. The tombstone probe searches for "name=Gone*", because a
// deleted object's name is mangled to "Gone\0ADEL:<guid>" — without wildcard
// support that probe matches nothing and every already-exists looks live.
func matchValue(have, want string) bool {
	if !strings.Contains(want, "*") {
		return strings.EqualFold(have, want)
	}
	parts := strings.Split(strings.ToLower(want), "*")
	h := strings.ToLower(have)
	if pre := parts[0]; pre != "" {
		if !strings.HasPrefix(h, pre) {
			return false
		}
		h = h[len(pre):]
	}
	last := parts[len(parts)-1]
	if last != "" {
		if !strings.HasSuffix(h, last) {
			return false
		}
		h = h[:len(h)-len(last)]
	}
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		i := strings.Index(h, mid)
		if i < 0 {
			return false
		}
		h = h[i+len(mid):]
	}
	return true
}

// unescapeFilterValue reverses RFC 4515 escaping. Every assertion value this
// module emits is escaped — a binary objectGUID becomes \01\00..., and a DN
// containing a backslash becomes \5c — so a matcher comparing against the
// escaped text matches nothing at all.
func unescapeFilterValue(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+2 >= len(s) {
			out = append(out, s[i])
			continue
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			out = append(out, s[i])
			continue
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return string(out)
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func lookupFold(attrs map[string][][]byte, name string) ([][]byte, bool) {
	for k, v := range attrs {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

// splitTerms splits a conjunction's body into balanced parenthesised terms.
func splitTerms(s string) []string {
	var (
		out   []string
		depth int
		start int
	)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				out = append(out, s[start:i+1])
			}
		}
	}
	return out
}

func (s *Server) handleAdd(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationAddResponse),
		gldap.WithResponseCode(gldap.ResultOperationsError))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetAddMessage()
	if err != nil {
		return
	}
	if s.exists(m.DN) {
		resp = r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationAddResponse),
			gldap.WithResponseCode(gldap.ResultEntryAlreadyExists),
			// AD prefixes its diagnostics with the Win32 code; the classifier
			// reads it, so the harness must emit it too or that path is never
			// exercised in CI.
			gldap.WithDiagnosticMessage("00002071: UpdErr: DSID-030F1173, problem 6005 (ENTRY_EXISTS), data 0"))
		return
	}

	attrs := make(map[string][][]byte, len(m.Attributes)+3)
	for _, a := range m.Attributes {
		vals := make([][]byte, 0, len(a.Vals))
		for _, v := range a.Vals {
			vals = append(vals, []byte(v))
		}
		attrs[a.Type] = vals
	}
	// A DC stamps these; a client never sends them.
	attrs["objectGUID"] = [][]byte{s.nextGUID()}
	attrs["distinguishedName"] = [][]byte{[]byte(m.DN)}
	attrs["name"] = [][]byte{[]byte(rdnValue(m.DN))}
	s.Seed(m.DN, attrs)

	resp = r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationAddResponse),
		gldap.WithResponseCode(gldap.ResultSuccess))
}

func (s *Server) handleModify(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultOperationsError))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetModifyMessage()
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := ""
	for dn := range s.entries {
		if equalFoldDN(dn, m.DN) {
			key = dn
			break
		}
	}
	if key == "" {
		resp = r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultNoSuchObject),
			gldap.WithDiagnosticMessage("0000208D: NameErr: DSID-03100238, problem 2001 (NO_OBJECT), data 0"))
		return
	}

	for _, ch := range m.Changes {
		name := ch.Modification.Type
		vals := make([][]byte, 0, len(ch.Modification.Vals))
		for _, v := range ch.Modification.Vals {
			vals = append(vals, []byte(v))
		}
		existing, _ := lookupFold(s.entries[key], name)
		switch ch.Operation {
		case int64(gldap.AddAttribute):
			s.entries[key][name] = append(existing, vals...)
		case int64(gldap.DeleteAttribute):
			if len(vals) == 0 {
				delete(s.entries[key], name)
				continue
			}
			s.entries[key][name] = without(existing, vals)
		default: // replace
			if len(vals) == 0 {
				delete(s.entries[key], name)
				continue
			}
			s.entries[key][name] = vals
		}
	}
	resp = r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultSuccess))
}

func without(have [][]byte, drop [][]byte) [][]byte {
	out := make([][]byte, 0, len(have))
	for _, h := range have {
		keep := true
		for _, d := range drop {
			if strings.EqualFold(string(h), string(d)) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) handleDelete(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationDelResponse),
		gldap.WithResponseCode(gldap.ResultOperationsError))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetDeleteMessage()
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for dn := range s.entries {
		if equalFoldDN(dn, m.DN) {
			delete(s.entries, dn)
			resp = r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationDelResponse),
				gldap.WithResponseCode(gldap.ResultSuccess))
			return
		}
	}
	resp = r.NewResponse(gldap.WithApplicationCode(gldap.ApplicationDelResponse),
		gldap.WithResponseCode(gldap.ResultNoSuchObject),
		gldap.WithDiagnosticMessage("0000208D: NameErr: DSID-03100238, problem 2001 (NO_OBJECT), data 0"))
}

// showDeletedOID is repeated rather than imported from adldap: importing the
// parent package from a package it imports would be a cycle.
const showDeletedOID = "1.2.840.113556.1.4.417"

func hasGldapControl(controls []gldap.Control, oid string) bool {
	for _, c := range controls {
		if c.GetControlType() == oid {
			return true
		}
	}
	return false
}
