// Copyright 2026 Ampas Labs Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ldaptest has a stand-in for a directory server that behaves
// like Microsoft Active Directory, for tests.
//
// It speaks real LDAP (over TLS, or with StartTLS) and knows just enough
// of it for the CA's login: simple binds, searches with the filters the
// CA sends (and, or, not, equality, presence, and AD's "in chain" rule for
// nested groups), and StartTLS.
//
// Like Windows Server AD, it answers "success" to a bind with a name and
// an empty password (an unauthenticated bind, RFC 4513). The CA must never
// send one; tests check that it does not. (Samba refuses such a bind by
// itself, so the Samba test cannot show this.)
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// The directory's names.
const (
	BaseDN          = "DC=corp,DC=example,DC=com"
	GroupBaseDN     = "OU=Groups,DC=corp,DC=example,DC=com"
	ServiceDN       = "CN=bastionxp-ca,OU=Service,DC=corp,DC=example,DC=com"
	ServicePassword = "service-secret"
)

// User is a person in the directory.
type User struct {
	DN       string // e.g. "CN=Alice,OU=People,DC=corp,DC=example,DC=com"
	SAM      string // sAMAccountName, e.g. "alice"
	UPN      string // userPrincipalName, e.g. "alice@corp.example.com"
	Password string
	Disabled bool
}

// Group is a group in the directory. Members are names (DNs) of people or
// of other groups.
type Group struct {
	DN      string
	Members []string
}

// Bind is one bind the fake received.
type Bind struct {
	DN          string
	HadPassword bool
}

// Fake is a stand-in for a directory server.
type Fake struct {
	listener net.Listener
	startTLS bool // plain LDAP that must be upgraded with StartTLS
	tls      *tls.Config
	roots    *x509.CertPool
	certPEM  []byte
	wg       sync.WaitGroup

	mu      sync.Mutex
	users   []User
	groups  []Group
	binds   []Bind
	filters []string
	conns   map[net.Conn]bool
	closed  bool
}

// NewFake starts a fake directory on LDAPS. Close it at the end of the test.
func NewFake() *Fake { return start(false) }

// NewStartTLSFake starts a fake directory on plain LDAP that must be
// upgraded with StartTLS before a bind. Close it at the end of the test.
func NewStartTLSFake() *Fake { return start(true) }

func start(startTLS bool) *Fake {
	cert, roots := selfSigned()
	f := &Fake{
		certPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		startTLS: startTLS,
		tls:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		roots:    roots,
		conns:    make(map[net.Conn]bool),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	if !startTLS {
		listener = tls.NewListener(listener, f.tls)
	}
	f.listener = listener
	f.wg.Add(1)
	go f.serve()
	return f
}

// URL is the address of the fake, e.g. "ldaps://127.0.0.1:50123".
func (f *Fake) URL() string {
	if f.startTLS {
		return "ldap://" + f.listener.Addr().String()
	}
	return "ldaps://" + f.listener.Addr().String()
}

// RootCAs trusts the fake's certificate.
func (f *Fake) RootCAs() *x509.CertPool { return f.roots }

// CertPEM is the fake's certificate in PEM, for a CA file.
func (f *Fake) CertPEM() []byte { return f.certPEM }

// AddUser puts a person into the directory.
func (f *Fake) AddUser(u User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, u)
}

// AddGroup puts a group into the directory.
func (f *Fake) AddGroup(g Group) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = append(f.groups, g)
}

// Binds returns the binds received so far.
func (f *Fake) Binds() []Bind {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Bind(nil), f.binds...)
}

// Filters returns the search filters received so far.
func (f *Fake) Filters() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.filters...)
}

// Close stops the fake and drops all connections.
func (f *Fake) Close() {
	f.mu.Lock()
	f.closed = true
	for conn := range f.conns {
		conn.Close()
	}
	f.mu.Unlock()
	f.listener.Close()
	f.wg.Wait()
}

func (f *Fake) serve() {
	defer f.wg.Done()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			conn.Close()
			return
		}
		f.conns[conn] = true
		f.mu.Unlock()
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.handle(conn)
		}()
	}
}

// session is the state of one connection.
type session struct {
	conn      net.Conn
	encrypted bool
	boundDN   string // empty: anonymous
}

func (f *Fake) handle(conn net.Conn) {
	s := &session{conn: conn, encrypted: !f.startTLS}
	defer func() {
		f.mu.Lock()
		delete(f.conns, s.conn)
		f.mu.Unlock()
		s.conn.Close()
	}()
	for {
		packet, err := ber.ReadPacket(s.conn)
		if err != nil {
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		id, ok := packet.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := packet.Children[1]
		switch op.Tag {
		case goldap.ApplicationBindRequest:
			f.bind(s, id, op)
		case goldap.ApplicationSearchRequest:
			f.search(s, id, op)
		case goldap.ApplicationExtendedRequest:
			if !f.extended(s, id, op) {
				return
			}
		case goldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

func (f *Fake) bind(s *session, id int64, op *ber.Packet) {
	if len(op.Children) < 3 {
		reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultProtocolError, "")
		return
	}
	dn := str(op.Children[1])
	password := string(op.Children[2].Data.Bytes())
	f.mu.Lock()
	f.binds = append(f.binds, Bind{DN: dn, HadPassword: password != ""})
	f.mu.Unlock()

	if !s.encrypted {
		reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultConfidentialityRequired, "use TLS")
		return
	}
	// AD: a name with an empty password is an anonymous bind, and it
	// "succeeds".
	if password == "" {
		s.boundDN = ""
		reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultSuccess, "")
		return
	}
	if strings.EqualFold(dn, ServiceDN) && password == ServicePassword {
		s.boundDN = ServiceDN
		reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultSuccess, "")
		return
	}
	f.mu.Lock()
	var found *User
	for i := range f.users {
		if strings.EqualFold(f.users[i].DN, dn) {
			found = &f.users[i]
		}
	}
	f.mu.Unlock()
	if found != nil && found.Password == password && !found.Disabled {
		s.boundDN = found.DN
		reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultSuccess, "")
		return
	}
	s.boundDN = ""
	// AD's message for a wrong password.
	reply(s, id, goldap.ApplicationBindResponse, goldap.LDAPResultInvalidCredentials,
		"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563")
}

func (f *Fake) extended(s *session, id int64, op *ber.Packet) bool {
	if len(op.Children) == 0 || string(op.Children[0].Data.Bytes()) != "1.3.6.1.4.1.1466.20037" || s.encrypted {
		reply(s, id, goldap.ApplicationExtendedResponse, goldap.LDAPResultProtocolError, "")
		return true
	}
	reply(s, id, goldap.ApplicationExtendedResponse, goldap.LDAPResultSuccess, "")
	tlsConn := tls.Server(s.conn, f.tls)
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	f.mu.Lock()
	delete(f.conns, s.conn)
	f.conns[tlsConn] = true
	f.mu.Unlock()
	s.conn = tlsConn
	s.encrypted = true
	return true
}

// entry is a directory object as a search sees it.
type entry struct {
	dn    string
	attrs map[string][]string // lower-case names
}

func (f *Fake) search(s *session, id int64, op *ber.Packet) {
	if len(op.Children) < 8 {
		reply(s, id, goldap.ApplicationSearchResultDone, goldap.LDAPResultProtocolError, "")
		return
	}
	// AD wants a bound account to search.
	if s.boundDN == "" {
		reply(s, id, goldap.ApplicationSearchResultDone, goldap.LDAPResultOperationsError,
			"000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection")
		return
	}
	base := str(op.Children[0])
	sizeLimit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	if text, err := goldap.DecompileFilter(filter); err == nil {
		f.mu.Lock()
		f.filters = append(f.filters, text)
		f.mu.Unlock()
	}
	var wanted []string
	for _, attr := range op.Children[7].Children {
		wanted = append(wanted, strings.ToLower(str(attr)))
	}

	entries := f.entries()
	var matches []entry
	for _, e := range entries {
		if !under(e.dn, base) {
			continue
		}
		ok, err := matchFilter(filter, e, entries)
		if err != nil {
			reply(s, id, goldap.ApplicationSearchResultDone, goldap.LDAPResultUnwillingToPerform, err.Error())
			return
		}
		if ok {
			matches = append(matches, e)
		}
	}
	for i, e := range matches {
		if sizeLimit > 0 && int64(i) >= sizeLimit {
			reply(s, id, goldap.ApplicationSearchResultDone, goldap.LDAPResultSizeLimitExceeded, "")
			return
		}
		send(s, id, searchEntry(e, wanted))
	}
	reply(s, id, goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess, "")
}

func (f *Fake) entries() []entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var entries []entry
	for _, u := range f.users {
		uac := 512
		if u.Disabled {
			uac = 514
		}
		entries = append(entries, entry{dn: u.DN, attrs: map[string][]string{
			"objectclass":        {"top", "person", "user"},
			"samaccountname":     {u.SAM},
			"userprincipalname":  {u.UPN},
			"useraccountcontrol": {strconv.Itoa(uac)},
		}})
	}
	for _, g := range f.groups {
		rdn, _, _ := strings.Cut(g.DN, ",")
		_, cn, _ := strings.Cut(rdn, "=")
		entries = append(entries, entry{dn: g.DN, attrs: map[string][]string{
			"objectclass": {"top", "group"},
			"cn":          {cn},
			"member":      g.Members,
		}})
	}
	return entries
}

// The parts of a search filter, as tagged in LDAP.
const (
	filterAnd        = 0
	filterOr         = 1
	filterNot        = 2
	filterEquality   = 3
	filterPresent    = 7
	filterExtensible = 9
	inChain          = "1.2.840.113556.1.4.1941"
)

func matchFilter(p *ber.Packet, e entry, all []entry) (bool, error) {
	switch p.Tag {
	case filterAnd:
		for _, child := range p.Children {
			if ok, err := matchFilter(child, e, all); err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case filterOr:
		for _, child := range p.Children {
			if ok, err := matchFilter(child, e, all); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case filterNot:
		if len(p.Children) != 1 {
			return false, errors.New("bad not filter")
		}
		ok, err := matchFilter(p.Children[0], e, all)
		return !ok, err
	case filterEquality:
		if len(p.Children) != 2 {
			return false, errors.New("bad equality filter")
		}
		attr := strings.ToLower(str(p.Children[0]))
		value := string(p.Children[1].Data.Bytes())
		for _, v := range e.attrs[attr] {
			if strings.EqualFold(v, value) {
				return true, nil
			}
		}
		return false, nil
	case filterPresent:
		return len(e.attrs[strings.ToLower(string(p.Data.Bytes()))]) > 0, nil
	case filterExtensible:
		var rule, attr, value string
		for _, child := range p.Children {
			switch child.Tag {
			case 1:
				rule = string(child.Data.Bytes())
			case 2:
				attr = strings.ToLower(string(child.Data.Bytes()))
			case 3:
				value = string(child.Data.Bytes())
			}
		}
		if rule != inChain || attr != "member" {
			return false, fmt.Errorf("matching rule %s on %s not supported by the fake", rule, attr)
		}
		return memberInChain(e, value, all, map[string]bool{}), nil
	default:
		return false, fmt.Errorf("filter type %d not supported by the fake", p.Tag)
	}
}

// memberInChain reports whether dn is a member of group e, directly or
// through other groups.
func memberInChain(e entry, dn string, all []entry, seen map[string]bool) bool {
	key := strings.ToLower(e.dn)
	if seen[key] {
		return false
	}
	seen[key] = true
	for _, member := range e.attrs["member"] {
		if strings.EqualFold(member, dn) {
			return true
		}
		for _, other := range all {
			if strings.EqualFold(other.dn, member) && len(other.attrs["member"]) > 0 &&
				memberInChain(other, dn, all, seen) {
				return true
			}
		}
	}
	return false
}

func under(dn, base string) bool {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return false
	}
	parsedBase, err := goldap.ParseDN(base)
	if err != nil {
		return false
	}
	return parsedBase.EqualFold(parsed) || parsedBase.AncestorOfFold(parsed)
}

func searchEntry(e entry, wanted []string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "DN"))
	attrs := ber.NewSequence("Attributes")
	for name, values := range e.attrs {
		if len(wanted) > 0 && !contains(wanted, name) {
			continue
		}
		attr := ber.NewSequence("Attribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
		}
		attr.AppendChild(set)
		attrs.AppendChild(attr)
	}
	p.AppendChild(attrs)
	return p
}

func reply(s *session, id int64, tag ber.Tag, code uint16, message string) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "Result Code"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "Diagnostic Message"))
	send(s, id, p)
}

func send(s *session, id int64, op *ber.Packet) {
	msg := ber.NewSequence("LDAP Message")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "Message ID"))
	msg.AppendChild(op)
	_, _ = s.conn.Write(msg.Bytes())
}

func str(p *ber.Packet) string {
	if p.Data == nil {
		return ""
	}
	return p.Data.String()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// selfSigned makes a certificate for 127.0.0.1 and a pool that trusts it.
func selfSigned() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Directory"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
