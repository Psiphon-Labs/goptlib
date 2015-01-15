package pt

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

// testReadWriter is a bytes.Buffer backed io.ReadWriter used for testing.  The
// Read and Write routines are to be used by the component being tested.  Data
// can be written to and read back via the writeHex and readHex routines.
type testReadWriter struct {
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
}

func (c *testReadWriter) Read(buf []byte) (n int, err error) {
	return c.readBuf.Read(buf)
}

func (c *testReadWriter) Write(buf []byte) (n int, err error) {
	return c.writeBuf.Write(buf)
}

func (c *testReadWriter) writeHex(str string) (n int, err error) {
	var buf []byte
	if buf, err = hex.DecodeString(str); err != nil {
		return
	}
	return c.readBuf.Write(buf)
}

func (c *testReadWriter) readHex() string {
	return hex.EncodeToString(c.writeBuf.Bytes())
}

func (c *testReadWriter) toBufio() *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
}

func (c *testReadWriter) reset() {
	c.readBuf.Reset()
	c.writeBuf.Reset()
}

// TestAuthInvalidVersion tests auth negotiation with an invalid version.
func TestAuthInvalidVersion(t *testing.T) {
	c := new(testReadWriter)

	// VER = 03, NMETHODS = 01, METHODS = [00]
	c.writeHex("030100")
	var err error
	if _, err = socks5NegotiateAuth(c.toBufio()); err == nil {
		t.Error("socks5NegotiateAuth(InvalidVersion) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5NegotiateAuth(InvalidVersion) returned incorrect error type or not temporary")
	}
}

// TestAuthInvalidNMethods tests auth negotiaton with no methods.
func TestAuthInvalidNMethods(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 00
	c.writeHex("0500")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(No Methods) failed:", err)
	}
	if method != socksAuthNoAcceptableMethods {
		t.Error("socks5NegotiateAuth(No Methods) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "05ff" {
		t.Error("socks5NegotiateAuth(No Methods) invalid response:", msg)
	}
}

// TestAuthNoneRequired tests auth negotiaton with NO AUTHENTICATION REQUIRED.
func TestAuthNoneRequired(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [00]
	c.writeHex("050100")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(None) failed:", err)
	}
	if method != socksAuthNoneRequired {
		t.Error("socks5NegotiateAuth(None) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0500" {
		t.Error("socks5NegotiateAuth(None) invalid response:", msg)
	}
}

// TestAuthUsernamePassword tests auth negotiation with USERNAME/PASSWORD.
func TestAuthUsernamePassword(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [02]
	c.writeHex("050102")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(UsernamePassword) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socks5NegotiateAuth(UsernamePassword) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socks5NegotiateAuth(UsernamePassword) invalid response:", msg)
	}
}

// TestAuthBoth tests auth negotiation containing both NO AUTHENTICATION
// REQUIRED and USERNAME/PASSWORD.
func TestAuthBoth(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 02, METHODS = [00, 02]
	c.writeHex("05020002")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(Both) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socks5NegotiateAuth(Both) unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socks5NegotiateAuth(Both) invalid response:", msg)
	}
}

// TestAuthUnsupported tests auth negotiation with a unsupported method.
func TestAuthUnsupported(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 01, METHODS = [01] (GSSAPI)
	c.writeHex("050101")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(Unknown) failed:", err)
	}
	if method != socksAuthNoAcceptableMethods {
		t.Error("socks5NegotiateAuth(Unknown) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "05ff" {
		t.Error("socks5NegotiateAuth(Unknown) invalid response:", msg)
	}
}

// TestAuthUnsupported2 tests auth negotiation with supported and unsupported
// methods.
func TestAuthUnsupported2(t *testing.T) {
	c := new(testReadWriter)
	var err error
	var method byte

	// VER = 05, NMETHODS = 03, METHODS = [00,01,02]
	c.writeHex("0503000102")
	if method, err = socks5NegotiateAuth(c.toBufio()); err != nil {
		t.Error("socks5NegotiateAuth(Unknown2) failed:", err)
	}
	if method != socksAuthUsernamePassword {
		t.Error("socks5NegotiateAuth(Unknown2) picked unexpected method:", method)
	}
	if msg := c.readHex(); msg != "0502" {
		t.Error("socks5NegotiateAuth(Unknown2) invalid response:", msg)
	}
}

// TestRFC1929InvalidVersion tests RFC1929 auth with an invalid version.
func TestRFC1929InvalidVersion(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest
	var err error

	// VER = 03, ULEN = 5, UNAME = "ABCDE", PLEN = 5, PASSWD = "abcde"
	c.writeHex("03054142434445056162636465")
	if err = socks5Authenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socks5Authenticate(InvalidVersion) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5Authenticate(InvalidVersion) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socks5Authenticate(InvalidVersion) invalid response:", msg)
	}
}

// TestRFC1929InvalidUlen tests RFC1929 auth with an invalid ULEN.
func TestRFC1929InvalidUlen(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest
	var err error

	// VER = 01, ULEN = 0, UNAME = "", PLEN = 5, PASSWD = "abcde"
	c.writeHex("0100056162636465")
	if err = socks5Authenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socks5Authenticate(InvalidUlen) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5Authenticate(InvalidUlen) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socks5Authenticate(InvalidUlen) invalid response:", msg)
	}
}

// TestRFC1929InvalidPlen tests RFC1929 auth with an invalid PLEN.
func TestRFC1929InvalidPlen(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest
	var err error

	// VER = 01, ULEN = 5, UNAME = "ABCDE", PLEN = 0, PASSWD = ""
	c.writeHex("0105414243444500")
	if err = socks5Authenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socks5Authenticate(InvalidPlen) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5Authenticate(InvalidPlen) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socks5Authenticate(InvalidPlen) invalid response:", msg)
	}
}

// TestRFC1929InvalidArgs tests RFC1929 auth with invalid pt args.
func TestRFC1929InvalidPTArgs(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest
	var err error

	// VER = 01, ULEN = 5, UNAME = "ABCDE", PLEN = 5, PASSWD = "abcde"
	c.writeHex("01054142434445056162636465")
	if err = socks5Authenticate(c.toBufio(), socksAuthUsernamePassword, &req); err == nil {
		t.Error("socks5Authenticate(InvalidArgs) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5Authenticate(InvalidArgs) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "0101" {
		t.Error("socks5Authenticate(InvalidArgs) invalid response:", msg)
	}
}

// TestRFC1929Success tests RFC1929 auth with valid pt args.
func TestRFC1929Success(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 01, ULEN = 9, UNAME = "key=value", PLEN = 1, PASSWD = "\0"
	c.writeHex("01096b65793d76616c75650100")
	if err := socks5Authenticate(c.toBufio(), socksAuthUsernamePassword, &req); err != nil {
		t.Error("socks5Authenticate(Success) failed:", err)
	}
	if msg := c.readHex(); msg != "0100" {
		t.Error("socks5Authenticate(Success) invalid response:", msg)
	}
	v, ok := req.Args.Get("key")
	if v != "value" || !ok {
		t.Error("RFC1929 k,v parse failure:", v)
	}
}

// TestRequestInvalidHdr tests SOCKS5 requests with invalid VER/CMD/RSV/ATYPE
func TestRequestInvalidHdr(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest
	var err error

	// VER = 03, CMD = 01, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("030100017f000001235a")
	if err = socks5ReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socks5ReadCommand(InvalidVer) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5ReadCommand(InvalidVer) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "05010001000000000000" {
		t.Error("socks5ReadCommand(InvalidVer) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 05, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050500017f000001235a")
	if err = socks5ReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socks5ReadCommand(InvalidCmd) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5ReadCommand(InvalidCmd) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "05070001000000000000" {
		t.Error("socks5ReadCommand(InvalidCmd) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 01, RSV = 30, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050130017f000001235a")
	if err = socks5ReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socks5ReadCommand(InvalidRsv) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5ReadCommand(InvalidRsv) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "05010001000000000000" {
		t.Error("socks5ReadCommand(InvalidRsv) invalid response:", msg)
	}
	c.reset()

	// VER = 05, CMD = 01, RSV = 01, ATYPE = 05, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050100057f000001235a")
	if err = socks5ReadCommand(c.toBufio(), &req); err == nil {
		t.Error("socks5ReadCommand(InvalidAtype) succeded")
	}
	if e, ok := err.(net.Error); !ok || !e.Temporary() {
		t.Error("socks5ReadCommand(InvalidAtype) returned incorrect error type or not temporary")
	}
	if msg := c.readHex(); msg != "05080001000000000000" {
		t.Error("socks5Authenticate(InvalidAtype) invalid response:", msg)
	}
	c.reset()
}

// TestRequestIPv4 tests IPv4 SOCKS5 requests.
func TestRequestIPv4(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 01, DST.ADDR = 127.0.0.1, DST.PORT = 9050
	c.writeHex("050100017f000001235a")
	if err := socks5ReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socks5ReadCommand(IPv4) failed:", err)
	}
	addr, err := net.ResolveTCPAddr("tcp", req.Target)
	if err != nil {
		t.Error("net.ResolveTCPAddr failed:", err)
	}
	if !tcpAddrsEqual(addr, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9050}) {
		t.Error("Unexpected target:", addr)
	}
}

// TestRequestIPv6 tests IPv4 SOCKS5 requests.
func TestRequestIPv6(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 04, DST.ADDR = 0102:0304:0506:0708:090a:0b0c:0d0e:0f10, DST.PORT = 9050
	c.writeHex("050100040102030405060708090a0b0c0d0e0f10235a")
	if err := socks5ReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socks5ReadCommand(IPv6) failed:", err)
	}
	addr, err := net.ResolveTCPAddr("tcp", req.Target)
	if err != nil {
		t.Error("net.ResolveTCPAddr failed:", err)
	}
	if !tcpAddrsEqual(addr, &net.TCPAddr{IP: net.ParseIP("0102:0304:0506:0708:090a:0b0c:0d0e:0f10"), Port: 9050}) {
		t.Error("Unexpected target:", addr)
	}
}

// TestRequestFQDN tests FQDN (DOMAINNAME) SOCKS5 requests.
func TestRequestFQDN(t *testing.T) {
	c := new(testReadWriter)
	var req SocksRequest

	// VER = 05, CMD = 01, RSV = 00, ATYPE = 04, DST.ADDR = example.com, DST.PORT = 9050
	c.writeHex("050100030b6578616d706c652e636f6d235a")
	if err := socks5ReadCommand(c.toBufio(), &req); err != nil {
		t.Error("socks5ReadCommand(FQDN) failed:", err)
	}
	if req.Target != "example.com:9050" {
		t.Error("Unexpected target:", req.Target)
	}
}

// TestResponseNil tests nil address SOCKS5 responses.
func TestResponseNil(t *testing.T) {
	c := new(testReadWriter)

	b := c.toBufio()
	if err := sendSocks5ResponseGranted(b); err != nil {
		t.Error("sendSocks5ResponseGranted() failed:", err)
	}
	b.Flush()
	if msg := c.readHex(); msg != "05000001000000000000" {
		t.Error("sendSocks5ResponseGranted(nil) invalid response:", msg)
	}
}

var _ io.ReadWriter = (*testReadWriter)(nil)

/*
SOCKS4a tests
*/

func TestReadSocks4aConnect(t *testing.T) {
	badTests := [...][]byte{
		[]byte(""),
		// missing userid
		[]byte("\x04\x01\x12\x34\x01\x02\x03\x04"),
		// missing \x00 after userid
		[]byte("\x04\x01\x12\x34\x01\x02\x03\x04key=value"),
		// missing hostname
		[]byte("\x04\x01\x12\x34\x00\x00\x00\x01key=value\x00"),
		// missing \x00 after hostname
		[]byte("\x04\x01\x12\x34\x00\x00\x00\x01key=value\x00hostname"),
		// bad name–value mapping
		[]byte("\x04\x01\x12\x34\x00\x00\x00\x01userid\x00hostname\x00"),
		// bad version number
		[]byte("\x03\x01\x12\x34\x01\x02\x03\x04\x00"),
		// BIND request
		[]byte("\x04\x02\x12\x34\x01\x02\x03\x04\x00"),
		// SOCKS5
		[]byte("\x05\x01\x00"),
	}
	ipTests := [...]struct {
		input  []byte
		addr   net.TCPAddr
		userid string
	}{
		{
			[]byte("\x04\x01\x12\x34\x01\x02\x03\x04key=value\x00"),
			net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 0x1234},
			"key=value",
		},
		{
			[]byte("\x04\x01\x12\x34\x01\x02\x03\x04\x00"),
			net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 0x1234},
			"",
		},
	}
	hostnameTests := [...]struct {
		input  []byte
		target string
		userid string
	}{
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01key=value\x00hostname\x00"),
			"hostname:4660",
			"key=value",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01\x00hostname\x00"),
			"hostname:4660",
			"",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01key=value\x00\x00"),
			":4660",
			"key=value",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01\x00\x00"),
			":4660",
			"",
		},
	}

	for i, input := range badTests {
		_, err := readSocks4aConnect(bufio.NewReader(bytes.NewReader(input)))
		if err == nil {
			t.Errorf("input %d: %q unexpectedly succeeded", i, input)
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			t.Error("readSocks4aConnect(badTests) returned incorrect error type or not temporary")
		}
	}

	for i, test := range ipTests {
		req, err := readSocks4aConnect(bufio.NewReader(bytes.NewReader(test.input)))
		if err != nil {
			t.Errorf("input %d: %q unexpectedly returned an error: %s", i, test.input, err)
		}
		addr, err := net.ResolveTCPAddr("tcp", req.Target)
		if err != nil {
			t.Errorf("input %d: %q → target %q: cannot resolve: %s", i, test.input,
				req.Target, err)
		}
		if !tcpAddrsEqual(addr, &test.addr) {
			t.Errorf("input %d: %q → address %s (expected %s)", i, test.input,
				req.Target, test.addr.String())
		}
		if req.Username != test.userid {
			t.Errorf("input %d: %q → username %q (expected %q)", i, test.input,
				req.Username, test.userid)
		}
		if req.Args == nil {
			t.Errorf("input %d: %q → unexpected nil Args from username %q", i, test.input, req.Username)
		}
	}

	for i, test := range hostnameTests {
		req, err := readSocks4aConnect(bufio.NewReader(bytes.NewReader(test.input)))
		if err != nil {
			t.Errorf("input %d: %q unexpectedly returned an error: %s", i, test.input, err)
		}
		if req.Target != test.target {
			t.Errorf("input %d: %q → target %q (expected %q)", i, test.input,
				req.Target, test.target)
		}
		if req.Username != test.userid {
			t.Errorf("input %d: %q → username %q (expected %q)", i, test.input,
				req.Username, test.userid)
		}
		if req.Args == nil {
			t.Errorf("input %d: %q → unexpected nil Args from username %q", i, test.input, req.Username)
		}
	}
}

func TestSendSocks4aResponse(t *testing.T) {
	tests := [...]struct {
		code     byte
		addr     net.TCPAddr
		expected []byte
	}{
		{
			socks4RequestGranted,
			net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 0x1234},
			[]byte("\x00\x5a\x12\x34\x01\x02\x03\x04"),
		},
		{
			socks4RequestRejected,
			net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 0x1234},
			[]byte("\x00\x5b\x12\x34\x00\x00\x00\x00"),
		},
	}

	for _, test := range tests {
		var buf bytes.Buffer
		err := sendSocks4aResponse(&buf, test.code, &test.addr)
		if err != nil {
			t.Errorf("0x%02x %s unexpectedly returned an error: %s", test.code, &test.addr, err)
		}
		p := make([]byte, 1024)
		n, err := buf.Read(p)
		if err != nil {
			t.Fatal(err)
		}
		output := p[:n]
		if !bytes.Equal(output, test.expected) {
			t.Errorf("0x%02x %s → %v (expected %v)",
				test.code, &test.addr, output, test.expected)
		}
	}
}
