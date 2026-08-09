package main

import (
	"solod.dev/so/crypto/crand"
	"solod.dev/so/encoding/hex"
	"solod.dev/so/net/netip"
	"solod.dev/so/testing"

	"github.com/jedisct1/go-ipcrypt/so/ipcrypt"
)

// vector is one entry of the IPCrypt reference test vectors.
type vector struct {
	key   string
	ip    string
	tweak string
	out   string
}

// decodeHex decodes s into dst and returns the filled prefix.
func decodeHex(dst []byte, s string) []byte {
	n, err := hex.Decode(dst, []byte(s))
	if err != nil {
		panic("test vector is not valid hex")
	}
	return dst[:n]
}

// bytesEqual compares two byte slices.
// The string conversion is a zero-copy view in So, which is how the standard
// library does it too.
func bytesEqual(a, b []byte) bool {
	return string(a) == string(b)
}

func TestDeterministicVectors(t *testing.T) {
	vectors := []vector{
		{
			key: "0123456789abcdeffedcba9876543210",
			ip:  "0.0.0.0",
			out: "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb",
		},
		{
			key: "1032547698badcfeefcdab8967452301",
			ip:  "255.255.255.255",
			out: "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8",
		},
		{
			key: "2b7e151628aed2a6abf7158809cf4f3c",
			ip:  "192.0.2.1",
			out: "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777",
		},
	}

	var keyBuf [16]byte
	var strBuf [netip.MaxAddrLen]byte
	for i := 0; i < len(vectors); i++ {
		v := vectors[i]
		key := decodeHex(keyBuf[:], v.key)
		ip := netip.MustParseAddr(v.ip)

		encrypted, err := ipcrypt.EncryptIP(key, ip)
		if err != nil {
			t.Error("EncryptIP failed")
			continue
		}
		if encrypted.String(strBuf[:]) != v.out {
			t.Error("EncryptIP output does not match the reference vector")
		}

		decrypted, err := ipcrypt.DecryptIP(key, encrypted)
		if err != nil {
			t.Error("DecryptIP failed")
			continue
		}
		if !decrypted.Unmap().Equal(ip) {
			t.Error("DecryptIP did not recover the original address")
		}
	}
}

func TestNDVectors(t *testing.T) {
	vectors := []vector{
		{
			key:   "0123456789abcdeffedcba9876543210",
			ip:    "0.0.0.0",
			tweak: "08e0c289bff23b7c",
			out:   "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16",
		},
		{
			key:   "1032547698badcfeefcdab8967452301",
			ip:    "192.0.2.1",
			tweak: "21bd1834bc088cd2",
			out:   "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad",
		},
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c",
			ip:    "2001:db8::1",
			tweak: "b4ecbe30b70898d7",
			out:   "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96",
		},
	}

	var keyBuf [16]byte
	var tweakBuf [8]byte
	var wantBuf [ipcrypt.NDSize]byte
	var dst [ipcrypt.NDSize]byte
	for i := 0; i < len(vectors); i++ {
		v := vectors[i]
		key := decodeHex(keyBuf[:], v.key)
		tweak := decodeHex(tweakBuf[:], v.tweak)
		want := decodeHex(wantBuf[:], v.out)
		ip := netip.MustParseAddr(v.ip)

		got, err := ipcrypt.EncryptIPND(dst[:], key, ip, tweak)
		if err != nil {
			t.Error("EncryptIPND failed")
			continue
		}
		if !bytesEqual(got, want) {
			t.Error("EncryptIPND output does not match the reference vector")
		}

		decrypted, err := ipcrypt.DecryptIPND(key, got)
		if err != nil {
			t.Error("DecryptIPND failed")
			continue
		}
		if !decrypted.Unmap().Equal(ip) {
			t.Error("DecryptIPND did not recover the original address")
		}
	}
}

func TestNDXVectors(t *testing.T) {
	vectors := []vector{
		{
			key:   "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
			ip:    "0.0.0.0",
			tweak: "21bd1834bc088cd2b4ecbe30b70898d7",
			out:   "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5",
		},
		{
			key:   "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
			ip:    "192.0.2.1",
			tweak: "08e0c289bff23b7cb4ecbe30b70898d7",
			out:   "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a",
		},
		{
			key:   "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
			ip:    "2001:db8::1",
			tweak: "21bd1834bc088cd2b4ecbe30b70898d7",
			out:   "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4",
		},
	}

	var keyBuf [32]byte
	var tweakBuf [16]byte
	var wantBuf [ipcrypt.NDXSize]byte
	var dst [ipcrypt.NDXSize]byte
	for i := 0; i < len(vectors); i++ {
		v := vectors[i]
		key := decodeHex(keyBuf[:], v.key)
		tweak := decodeHex(tweakBuf[:], v.tweak)
		want := decodeHex(wantBuf[:], v.out)
		ip := netip.MustParseAddr(v.ip)

		got, err := ipcrypt.EncryptIPNDX(dst[:], key, ip, tweak)
		if err != nil {
			t.Error("EncryptIPNDX failed")
			continue
		}
		if !bytesEqual(got, want) {
			t.Error("EncryptIPNDX output does not match the reference vector")
		}

		decrypted, err := ipcrypt.DecryptIPNDX(key, got)
		if err != nil {
			t.Error("DecryptIPNDX failed")
			continue
		}
		if !decrypted.Unmap().Equal(ip) {
			t.Error("DecryptIPNDX did not recover the original address")
		}
	}
}

func TestPfxVectors(t *testing.T) {
	const pfxKey = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
	vectors := []vector{
		{ip: "0.0.0.0", out: "151.82.155.134"},
		{ip: "255.255.255.255", out: "94.185.169.89"},
		{ip: "192.0.2.1", out: "100.115.72.131"},
		{ip: "2001:db8::1", out: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"},
		{ip: "2001:db8::2", out: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f8a"},
		{ip: "2001:db8:1234:5678:9abc:def0:1234:5678", out: "c180:5dd4:3f39:5792:2334:a348:e913:4af5"},
	}

	var keyBuf [32]byte
	key := decodeHex(keyBuf[:], pfxKey)

	var c ipcrypt.PfxCipher
	if err := c.Init(key); err != nil {
		t.Fatal("PfxCipher.Init failed")
		return
	}

	var strBuf [netip.MaxAddrLen]byte
	for i := 0; i < len(vectors); i++ {
		v := vectors[i]
		ip := netip.MustParseAddr(v.ip)

		encrypted, err := c.EncryptIP(ip)
		if err != nil {
			t.Error("PfxCipher.EncryptIP failed")
			continue
		}
		if encrypted.String(strBuf[:]) != v.out {
			t.Error("PfxCipher.EncryptIP output does not match the reference vector")
		}

		decrypted, err := c.DecryptIP(encrypted)
		if err != nil {
			t.Error("PfxCipher.DecryptIP failed")
			continue
		}
		if !decrypted.Equal(ip) {
			t.Error("PfxCipher.DecryptIP did not recover the original address")
		}
	}
}

// TestPfxPreservesPrefix checks the property the mode exists for: addresses
// sharing a prefix still share it once encrypted.
func TestPfxPreservesPrefix(t *testing.T) {
	var keyBuf [32]byte
	key := decodeHex(keyBuf[:], "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")

	first, err := ipcrypt.EncryptIPPfx(key, netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal("EncryptIPPfx failed")
		return
	}
	second, err := ipcrypt.EncryptIPPfx(key, netip.MustParseAddr("2001:db8::2"))
	if err != nil {
		t.Fatal("EncryptIPPfx failed")
		return
	}

	var a16, b16 [16]byte
	a16 = first.As16(a16)
	b16 = second.As16(b16)
	for i := 0; i < 14; i++ {
		if a16[i] != b16[i] {
			t.Error("two addresses sharing a prefix lost it once encrypted")
			return
		}
	}
}

// TestRandomTweak covers the path where the package draws the tweak itself.
func TestRandomTweak(t *testing.T) {
	var keyBuf [32]byte
	key := decodeHex(keyBuf[:], "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := netip.MustParseAddr("192.0.2.1")

	var ndDst, ndOther [ipcrypt.NDSize]byte
	nd, err := ipcrypt.EncryptIPND(ndDst[:], key[:16], ip, nil)
	if err != nil {
		t.Fatal("EncryptIPND with a random tweak failed")
		return
	}
	other, err := ipcrypt.EncryptIPND(ndOther[:], key[:16], ip, nil)
	if err != nil {
		t.Fatal("EncryptIPND with a random tweak failed")
		return
	}
	if bytesEqual(nd, other) {
		t.Error("two random tweaks produced the same ciphertext")
	}
	decrypted, err := ipcrypt.DecryptIPND(key[:16], nd)
	if err != nil {
		t.Fatal("DecryptIPND failed")
		return
	}
	if !decrypted.Unmap().Equal(ip) {
		t.Error("DecryptIPND did not recover the original address")
	}

	var ndxDst [ipcrypt.NDXSize]byte
	ndx, err := ipcrypt.EncryptIPNDX(ndxDst[:], key, ip, nil)
	if err != nil {
		t.Fatal("EncryptIPNDX with a random tweak failed")
		return
	}
	decrypted, err = ipcrypt.DecryptIPNDX(key, ndx)
	if err != nil {
		t.Fatal("DecryptIPNDX failed")
		return
	}
	if !decrypted.Unmap().Equal(ip) {
		t.Error("DecryptIPNDX did not recover the original address")
	}
}

func TestKiasuBC(t *testing.T) {
	var key [16]byte
	var tweak [8]byte
	var block [16]byte
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		block[i] = byte(0xf0 - i)
	}
	for i := 0; i < 8; i++ {
		tweak[i] = byte(0x10 + i)
	}

	var encrypted [16]byte
	ciphertext, err := ipcrypt.KiasuBCEncrypt(encrypted[:], key[:], tweak[:], block[:])
	if err != nil {
		t.Fatal("KiasuBCEncrypt failed")
		return
	}
	if bytesEqual(ciphertext, block[:]) {
		t.Error("KiasuBCEncrypt returned the plaintext")
	}

	var decrypted [16]byte
	plaintext, err := ipcrypt.KiasuBCDecrypt(decrypted[:], key[:], tweak[:], ciphertext)
	if err != nil {
		t.Fatal("KiasuBCDecrypt failed")
		return
	}
	if !bytesEqual(plaintext, block[:]) {
		t.Error("KiasuBCDecrypt did not recover the plaintext")
	}

	// A different tweak must give a different result.
	tweak[0] ^= 1
	var other [16]byte
	otherCiphertext, err := ipcrypt.KiasuBCEncrypt(other[:], key[:], tweak[:], block[:])
	if err != nil {
		t.Fatal("KiasuBCEncrypt failed")
		return
	}
	if bytesEqual(otherCiphertext, ciphertext) {
		t.Error("KIASU-BC ignored the tweak")
	}
}

func TestInvalidInputs(t *testing.T) {
	var keyBuf [32]byte
	key := decodeHex(keyBuf[:], "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := netip.MustParseAddr("192.0.2.1")

	if _, err := ipcrypt.EncryptIP(key[:15], ip); err != ipcrypt.ErrInvalidKeySize {
		t.Error("a short key should be rejected")
	}

	var zero netip.Addr
	if _, err := ipcrypt.EncryptIP(key[:16], zero); err != ipcrypt.ErrInvalidIP {
		t.Error("the zero address should be rejected")
	}

	var tooSmall [ipcrypt.NDSize - 1]byte
	if _, err := ipcrypt.EncryptIPND(tooSmall[:], key[:16], ip, nil); err != ipcrypt.ErrShortBuffer {
		t.Error("a short destination buffer should be rejected")
	}

	var dst [ipcrypt.NDSize]byte
	if _, err := ipcrypt.EncryptIPND(dst[:], key[:16], ip, key[:7]); err != ipcrypt.ErrInvalidTweakSize {
		t.Error("a short tweak should be rejected")
	}

	if _, err := ipcrypt.DecryptIPND(key[:16], dst[:ipcrypt.NDSize-1]); err != ipcrypt.ErrInvalidCiphertext {
		t.Error("a truncated ciphertext should be rejected")
	}

	var dstX [ipcrypt.NDXSize]byte
	if _, err := ipcrypt.EncryptIPNDX(dstX[:ipcrypt.NDXSize-1], key[:], ip, nil); err != ipcrypt.ErrShortBuffer {
		t.Error("a short ndx destination buffer should be rejected")
	}
	if _, err := ipcrypt.DecryptIPNDX(key[:], dstX[:ipcrypt.NDXSize-1]); err != ipcrypt.ErrInvalidCiphertext {
		t.Error("a truncated ndx ciphertext should be rejected")
	}

	var repeated [32]byte
	copy(repeated[:16], key[:16])
	copy(repeated[16:], key[:16])
	if _, err := ipcrypt.EncryptIPPfx(repeated[:], ip); err != ipcrypt.ErrKeyHalvesEqual {
		t.Error("a pfx key with two identical halves should be rejected")
	}

	var block [16]byte
	if _, err := ipcrypt.KiasuBCEncrypt(block[:15], key[:16], key[:8], block[:]); err != ipcrypt.ErrShortBuffer {
		t.Error("a short KIASU-BC destination buffer should be rejected")
	}
	if _, err := ipcrypt.KiasuBCEncrypt(block[:], key[:16], key[:8], block[:15]); err != ipcrypt.ErrInvalidBlockSize {
		t.Error("a KIASU-BC block that is not 16 bytes should be rejected")
	}
	if _, err := ipcrypt.KiasuBCDecrypt(block[:], key[:16], key[:7], block[:]); err != ipcrypt.ErrInvalidTweakSize {
		t.Error("a KIASU-BC tweak that is not 8 bytes should be rejected")
	}
}

// TestUninitializedCiphers checks that every cipher refuses to work until Init
// has succeeded, rather than running under an all-zero key.
func TestUninitializedCiphers(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	var dst [ipcrypt.NDXSize]byte

	var det ipcrypt.DeterministicCipher
	if _, err := det.EncryptIP(ip); err != ipcrypt.ErrUninitialized {
		t.Error("DeterministicCipher.EncryptIP without a key should be rejected")
	}
	if _, err := det.DecryptIP(ip); err != ipcrypt.ErrUninitialized {
		t.Error("DeterministicCipher.DecryptIP without a key should be rejected")
	}

	var nd ipcrypt.NonDeterministicCipher
	if _, err := nd.EncryptIP(dst[:], ip, nil); err != ipcrypt.ErrUninitialized {
		t.Error("NonDeterministicCipher.EncryptIP without a key should be rejected")
	}
	if _, err := nd.DecryptIP(dst[:ipcrypt.NDSize]); err != ipcrypt.ErrUninitialized {
		t.Error("NonDeterministicCipher.DecryptIP without a key should be rejected")
	}

	var ndx ipcrypt.NonDeterministicXCipher
	if _, err := ndx.EncryptIP(dst[:], ip, nil); err != ipcrypt.ErrUninitialized {
		t.Error("NonDeterministicXCipher.EncryptIP without a key should be rejected")
	}
	if _, err := ndx.DecryptIP(dst[:]); err != ipcrypt.ErrUninitialized {
		t.Error("NonDeterministicXCipher.DecryptIP without a key should be rejected")
	}

	var pfx ipcrypt.PfxCipher
	if _, err := pfx.EncryptIP(ip); err != ipcrypt.ErrUninitialized {
		t.Error("PfxCipher.EncryptIP without a key should be rejected")
	}
	if _, err := pfx.DecryptIP(ip); err != ipcrypt.ErrUninitialized {
		t.Error("PfxCipher.DecryptIP without a key should be rejected")
	}

	// A failed Init must leave the cipher just as unusable.
	var tooShort [16]byte
	if err := pfx.Init(tooShort[:]); err != ipcrypt.ErrInvalidKeySize {
		t.Error("a 16-byte pfx key should be rejected")
	}
	if _, err := pfx.EncryptIP(ip); err != ipcrypt.ErrUninitialized {
		t.Error("a cipher whose Init failed should stay unusable")
	}
}

// roundTrip encrypts and decrypts ip in all four modes and reports whether
// every one of them recovered it.
func roundTrip(t *testing.T, key []byte, ip netip.Addr) bool {
	encrypted, err := ipcrypt.EncryptIP(key[:16], ip)
	if err != nil {
		t.Error("EncryptIP failed")
		return false
	}
	decrypted, err := ipcrypt.DecryptIP(key[:16], encrypted)
	if err != nil {
		t.Error("DecryptIP failed")
		return false
	}
	if !decrypted.Unmap().Equal(ip) {
		t.Error("ipcrypt-deterministic did not round trip")
		return false
	}

	var ndBuf [ipcrypt.NDSize]byte
	nd, err := ipcrypt.EncryptIPND(ndBuf[:], key[:16], ip, nil)
	if err != nil {
		t.Error("EncryptIPND failed")
		return false
	}
	decrypted, err = ipcrypt.DecryptIPND(key[:16], nd)
	if err != nil {
		t.Error("DecryptIPND failed")
		return false
	}
	if !decrypted.Unmap().Equal(ip) {
		t.Error("ipcrypt-nd did not round trip")
		return false
	}

	var ndxBuf [ipcrypt.NDXSize]byte
	ndx, err := ipcrypt.EncryptIPNDX(ndxBuf[:], key, ip, nil)
	if err != nil {
		t.Error("EncryptIPNDX failed")
		return false
	}
	decrypted, err = ipcrypt.DecryptIPNDX(key, ndx)
	if err != nil {
		t.Error("DecryptIPNDX failed")
		return false
	}
	if !decrypted.Unmap().Equal(ip) {
		t.Error("ipcrypt-ndx did not round trip")
		return false
	}

	pfx, err := ipcrypt.EncryptIPPfx(key, ip)
	if err != nil {
		t.Error("EncryptIPPfx failed")
		return false
	}
	if pfx.Is4() != ip.Is4() {
		t.Error("ipcrypt-pfx changed the address family")
		return false
	}
	decrypted, err = ipcrypt.DecryptIPPfx(key, pfx)
	if err != nil {
		t.Error("DecryptIPPfx failed")
		return false
	}
	if !decrypted.Equal(ip) {
		t.Error("ipcrypt-pfx did not round trip")
		return false
	}
	return true
}

// TestRandomRoundTrips runs every mode over random keys and addresses.
// The Go test file covers the same ground, but only this one reaches the C
// build, where a codegen problem would show up.
func TestRandomRoundTrips(t *testing.T) {
	var key [32]byte
	var a16 [16]byte
	var a4 [4]byte

	for round := 0; round < 64; round++ {
		if _, err := crand.Read(key[:]); err != nil {
			t.Fatal("crand.Read failed")
			return
		}
		if _, err := crand.Read(a16[:]); err != nil {
			t.Fatal("crand.Read failed")
			return
		}
		if _, err := crand.Read(a4[:]); err != nil {
			t.Fatal("crand.Read failed")
			return
		}

		if !roundTrip(t, key[:], netip.AddrFrom16(a16)) {
			return
		}
		if !roundTrip(t, key[:], netip.AddrFrom4(a4)) {
			return
		}
	}
}
