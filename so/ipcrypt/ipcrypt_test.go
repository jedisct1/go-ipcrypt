// These tests run under the regular Go toolchain, which never transpiles them.
// They cover what the So test suite cannot: the software AES against
// crypto/aes, and the agreement of the two toolchains on the reference vectors.
//
// The full vectors and the error paths live in test/ipcrypt.go, under
// `so test`.
package ipcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"solod.dev/so/net/netip"
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestAESMatchesStdlib checks the portable AES-128 core against crypto/aes.
func TestAESMatchesStdlib(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 16)
	got := make([]byte, 16)
	want := make([]byte, 16)

	for i := 0; i < 1000; i++ {
		rand.Read(key)
		rand.Read(src)

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}

		var rk roundKeys
		expandKey(&rk, key)

		block.Encrypt(want, src)
		encryptBlock(got, &rk, src)
		if !bytes.Equal(got, want) {
			t.Fatalf("encryptBlock(%x, %x) = %x, want %x", key, src, got, want)
		}

		block.Decrypt(want, src)
		decryptBlock(got, &rk, src)
		if !bytes.Equal(got, want) {
			t.Fatalf("decryptBlock(%x, %x) = %x, want %x", key, src, got, want)
		}
	}
}

// TestKiasuZeroTweakIsAES checks the defining property of KIASU-BC: with an
// all-zero tweak it degenerates to plain AES-128.
func TestKiasuZeroTweakIsAES(t *testing.T) {
	key := make([]byte, 16)
	src := make([]byte, 16)
	tweak := make([]byte, TweakSize)
	got := make([]byte, 16)
	want := make([]byte, 16)

	for i := 0; i < 100; i++ {
		rand.Read(key)
		rand.Read(src)

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("aes.NewCipher: %v", err)
		}
		block.Encrypt(want, src)

		var rk roundKeys
		expandKey(&rk, key)
		kiasuEncrypt(got, &rk, tweak, src)
		if !bytes.Equal(got, want) {
			t.Fatalf("kiasuEncrypt with a zero tweak = %x, want %x", got, want)
		}

		kiasuDecrypt(got, &rk, tweak, want)
		if !bytes.Equal(got, src) {
			t.Fatalf("kiasuDecrypt with a zero tweak = %x, want %x", got, src)
		}
	}
}

// TestReferenceVectors checks that both toolchains produce the same answers,
// one vector per mode.
func TestReferenceVectors(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")

	encrypted, err := EncryptIP(mustDecode(t, "2b7e151628aed2a6abf7158809cf4f3c"), ip)
	if err != nil {
		t.Fatalf("EncryptIP: %v", err)
	}
	var strBuf [netip.MaxAddrLen]byte
	if got := encrypted.String(strBuf[:]); got != "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777" {
		t.Errorf("ipcrypt-deterministic: got %s", got)
	}

	nd := make([]byte, NDSize)
	nd, err = EncryptIPND(nd, mustDecode(t, "1032547698badcfeefcdab8967452301"), ip,
		mustDecode(t, "21bd1834bc088cd2"))
	if err != nil {
		t.Fatalf("EncryptIPND: %v", err)
	}
	if got := hex.EncodeToString(nd); got != "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad" {
		t.Errorf("ipcrypt-nd: got %s", got)
	}

	ndx := make([]byte, NDXSize)
	ndx, err = EncryptIPNDX(ndx,
		mustDecode(t, "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210"), ip,
		mustDecode(t, "08e0c289bff23b7cb4ecbe30b70898d7"))
	if err != nil {
		t.Fatalf("EncryptIPNDX: %v", err)
	}
	if got := hex.EncodeToString(ndx); got != "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a" {
		t.Errorf("ipcrypt-ndx: got %s", got)
	}

	pfx, err := EncryptIPPfx(
		mustDecode(t, "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"), ip)
	if err != nil {
		t.Fatalf("EncryptIPPfx: %v", err)
	}
	if got := pfx.String(strBuf[:]); got != "100.115.72.131" {
		t.Errorf("ipcrypt-pfx: got %s", got)
	}
}

// TestRoundTrips exercises every mode over random keys and addresses.
func TestRoundTrips(t *testing.T) {
	key32 := make([]byte, 32)
	var a16 [16]byte
	var a4 [4]byte

	for i := 0; i < 200; i++ {
		rand.Read(key32)
		rand.Read(a16[:])
		rand.Read(a4[:])

		addrs := []netip.Addr{netip.AddrFrom16(a16), netip.AddrFrom4(a4)}
		for _, ip := range addrs {
			encrypted, err := EncryptIP(key32[:16], ip)
			if err != nil {
				t.Fatalf("EncryptIP: %v", err)
			}
			decrypted, err := DecryptIP(key32[:16], encrypted)
			if err != nil {
				t.Fatalf("DecryptIP: %v", err)
			}
			if !decrypted.Unmap().Equal(ip) {
				t.Fatalf("ipcrypt-deterministic round trip: got %v, want %v", decrypted, ip)
			}

			nd, err := EncryptIPND(make([]byte, NDSize), key32[:16], ip, nil)
			if err != nil {
				t.Fatalf("EncryptIPND: %v", err)
			}
			decrypted, err = DecryptIPND(key32[:16], nd)
			if err != nil {
				t.Fatalf("DecryptIPND: %v", err)
			}
			if !decrypted.Unmap().Equal(ip) {
				t.Fatalf("ipcrypt-nd round trip: got %v, want %v", decrypted, ip)
			}

			ndx, err := EncryptIPNDX(make([]byte, NDXSize), key32, ip, nil)
			if err != nil {
				t.Fatalf("EncryptIPNDX: %v", err)
			}
			decrypted, err = DecryptIPNDX(key32, ndx)
			if err != nil {
				t.Fatalf("DecryptIPNDX: %v", err)
			}
			if !decrypted.Unmap().Equal(ip) {
				t.Fatalf("ipcrypt-ndx round trip: got %v, want %v", decrypted, ip)
			}

			pfx, err := EncryptIPPfx(key32, ip)
			if err != nil {
				t.Fatalf("EncryptIPPfx: %v", err)
			}
			if pfx.Is4() != ip.Is4() {
				t.Fatalf("ipcrypt-pfx changed the address family of %v", ip)
			}
			decrypted, err = DecryptIPPfx(key32, pfx)
			if err != nil {
				t.Fatalf("DecryptIPPfx: %v", err)
			}
			if !decrypted.Equal(ip) {
				t.Fatalf("ipcrypt-pfx round trip: got %v, want %v", decrypted, ip)
			}
		}
	}
}
