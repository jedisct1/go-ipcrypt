// Package ipcrypt contains tests for the ipcrypt package.
package ipcrypt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// testVector represents a single test case for IP encryption/decryption.
type testVector struct {
	variant string
	key     string
	ip      string
	tweak   string
	output  string
}

var testVectors = []testVector{
	// ipcrypt-deterministic test vectors
	{
		variant: "ipcrypt-deterministic",
		key:     "0123456789abcdeffedcba9876543210",
		ip:      "0.0.0.0",
		output:  "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb",
	},
	{
		variant: "ipcrypt-deterministic",
		key:     "1032547698badcfeefcdab8967452301",
		ip:      "255.255.255.255",
		output:  "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8",
	},
	{
		variant: "ipcrypt-deterministic",
		key:     "2b7e151628aed2a6abf7158809cf4f3c",
		ip:      "192.0.2.1",
		output:  "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777",
	},
	{
		variant: "ipcrypt-deterministic",
		key:     "2b7e151628aed2a6abf7158809cf4f3c",
		ip:      "2001:db8::1",
		output:  "10ea:8047:d631:d47d:150d:53dc:6ff3:9302",
	},

	// ipcrypt-nd test vectors
	{
		variant: "ipcrypt-nd",
		key:     "0123456789abcdeffedcba9876543210",
		ip:      "0.0.0.0",
		tweak:   "08e0c289bff23b7c",
		output:  "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16",
	},
	{
		variant: "ipcrypt-nd",
		key:     "1032547698badcfeefcdab8967452301",
		ip:      "192.0.2.1",
		tweak:   "21bd1834bc088cd2",
		output:  "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad",
	},
	{
		variant: "ipcrypt-nd",
		key:     "2b7e151628aed2a6abf7158809cf4f3c",
		ip:      "2001:db8::1",
		tweak:   "b4ecbe30b70898d7",
		output:  "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96",
	},

	// ipcrypt-ndx test vectors
	{
		variant: "ipcrypt-ndx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "0.0.0.0",
		tweak:   "21bd1834bc088cd2b4ecbe30b70898d7",
		output:  "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5",
	},
	{
		variant: "ipcrypt-ndx",
		key:     "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
		ip:      "192.0.2.1",
		tweak:   "08e0c289bff23b7cb4ecbe30b70898d7",
		output:  "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a",
	},
	{
		variant: "ipcrypt-ndx",
		key:     "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
		ip:      "2001:db8::1",
		tweak:   "21bd1834bc088cd2b4ecbe30b70898d7",
		output:  "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4",
	},

	// ipcrypt-pfx test vectors
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "0.0.0.0",
		output:  "151.82.155.134",
	},
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "255.255.255.255",
		output:  "94.185.169.89",
	},
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "192.0.2.1",
		output:  "100.115.72.131",
	},
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "2001:db8::1",
		output:  "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88",
	},
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "2001:db8::2",
		output:  "c180:5dd4:2587:3524:30ab:fa65:6ab6:f8a",
	},
	{
		variant: "ipcrypt-pfx",
		key:     "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
		ip:      "2001:db8:1234:5678:9abc:def0:1234:5678",
		output:  "c180:5dd4:3f39:5792:2334:a348:e913:4af5",
	},
}

// TestReferenceVectors tests all reference vectors for correctness.
func TestReferenceVectors(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.variant+"/"+tv.ip, func(t *testing.T) {
			// Parse input IP
			ip := net.ParseIP(tv.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tv.ip)
			}

			// Parse key
			key, err := hex.DecodeString(tv.key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}

			// Variables for encryption/decryption
			var encrypted []byte
			var tweak []byte

			// Test encryption
			switch tv.variant {
			case "ipcrypt-deterministic":
				encryptedIP, err := EncryptIP(key, ip)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				encrypted = encryptedIP
			case "ipcrypt-nd":
				tweak, err = hex.DecodeString(tv.tweak)
				if err != nil {
					t.Fatalf("Failed to decode tweak: %v", err)
				}
				encrypted, err = EncryptIPNonDeterministic(ip.String(), key, tweak)
			case "ipcrypt-ndx":
				tweak, err = hex.DecodeString(tv.tweak)
				if err != nil {
					t.Fatalf("Failed to decode tweak: %v", err)
				}
				encrypted, err = EncryptIPNonDeterministicX(ip.String(), key, tweak)
			case "ipcrypt-pfx":
				encryptedIP, err := EncryptIPPfx(ip, key)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				encrypted = encryptedIP
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Compare output
			var got string
			switch tv.variant {
			case "ipcrypt-deterministic", "ipcrypt-pfx":
				got = net.IP(encrypted).String()
			case "ipcrypt-nd", "ipcrypt-ndx":
				got = hex.EncodeToString(encrypted)
			}
			if got != tv.output {
				t.Errorf("Encryption mismatch:\nGot:  %s\nWant: %s", got, tv.output)
			}

			// Test decryption
			var decrypted net.IP
			switch tv.variant {
			case "ipcrypt-deterministic":
				decrypted, err = DecryptIP(key, net.IP(encrypted))
			case "ipcrypt-nd":
				decryptedStr, err := DecryptIPNonDeterministic(encrypted, key)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
				decrypted = net.ParseIP(decryptedStr)
			case "ipcrypt-ndx":
				decryptedStr, err := DecryptIPNonDeterministicX(encrypted, key)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
				decrypted = net.ParseIP(decryptedStr)
			case "ipcrypt-pfx":
				decrypted, err = DecryptIPPfx(net.IP(encrypted), key)
			}
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Compare decrypted IP
			if !decrypted.Equal(ip) {
				t.Errorf("Decryption mismatch:\nGot:  %s\nWant: %s", decrypted, ip)
			}
		})
	}
}

func TestIPDeterministic(t *testing.T) {
	tests := []struct {
		key      string // hex-encoded key
		ip       string
		expected string
	}{
		{
			key:      "0123456789abcdeffedcba9876543210",
			ip:       "0.0.0.0",
			expected: "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb",
		},
		{
			key:      "1032547698badcfeefcdab8967452301",
			ip:       "255.255.255.255",
			expected: "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8",
		},
		{
			key:      "2b7e151628aed2a6abf7158809cf4f3c",
			ip:       "192.0.2.1",
			expected: "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777",
		},
	}

	for i, test := range tests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Errorf("Test %d: Failed to decode key: %v", i, err)
			continue
		}

		ip := net.ParseIP(test.ip)
		if ip == nil {
			t.Errorf("Test %d: Invalid IP address: %s", i, test.ip)
			continue
		}

		encrypted, err := EncryptIP(key, ip)
		if err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
			continue
		}

		got := encrypted.String()
		if got != test.expected {
			t.Errorf("Test %d: Encryption failed: got %s, want %s", i, got, test.expected)
			continue
		}

		decrypted, err := DecryptIP(key, encrypted)
		if err != nil {
			t.Errorf("Test %d: Decryption failed: %v", i, err)
			continue
		}

		if !decrypted.Equal(ip) {
			t.Errorf("Test %d: Decryption failed: got %s, want %s", i, decrypted, ip)
		}
	}
}

func TestIPNonDeterministic(t *testing.T) {
	tests := []struct {
		key      string // hex-encoded key
		ip       string
		tweak    string // hex-encoded tweak
		expected string // hex-encoded expected output (tweak + encrypted IP)
	}{
		{
			key:      "0123456789abcdeffedcba9876543210",
			ip:       "0.0.0.0",
			tweak:    "08e0c289bff23b7c",
			expected: "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16",
		},
		{
			key:      "1032547698badcfeefcdab8967452301",
			ip:       "192.0.2.1",
			tweak:    "21bd1834bc088cd2",
			expected: "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad",
		},
		{
			key:      "2b7e151628aed2a6abf7158809cf4f3c",
			ip:       "2001:db8::1",
			tweak:    "b4ecbe30b70898d7",
			expected: "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96",
		},
	}

	for i, test := range tests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Errorf("Test %d: Failed to decode key: %v", i, err)
			continue
		}

		// Use only first 16 bytes of the key
		if len(key) > KeySizeND {
			key = key[:KeySizeND]
		}

		tweak, err := hex.DecodeString(test.tweak)
		if err != nil {
			t.Errorf("Test %d: Failed to decode tweak: %v", i, err)
			continue
		}

		encrypted, err := EncryptIPNonDeterministic(test.ip, key, tweak)
		if err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
			continue
		}

		// Convert encrypted data to hex string for comparison
		encryptedHex := hex.EncodeToString(encrypted)
		if encryptedHex != test.expected {
			t.Errorf("Test %d: Encryption failed: got %s, want %s", i, encryptedHex, test.expected)
			continue
		}

		decrypted, err := DecryptIPNonDeterministic(encrypted, key)
		if err != nil {
			t.Errorf("Test %d: Decryption failed: %v", i, err)
			continue
		}

		if decrypted != test.ip {
			t.Errorf("Test %d: Decryption failed: got %s, want %s", i, decrypted, test.ip)
		}
	}

	// Test with random tweak
	key := make([]byte, KeySizeND)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	encrypted, err := EncryptIPNonDeterministic("192.168.1.1", key, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt with random tweak: %v", err)
	}

	decrypted, err := DecryptIPNonDeterministic(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt with random tweak: %v", err)
	}

	if decrypted != "192.168.1.1" {
		t.Errorf("Random tweak test failed: got %s, want %s", decrypted, "192.168.1.1")
	}
}

func TestIPNonDeterministicX(t *testing.T) {
	tests := []struct {
		key      string // hex-encoded key
		ip       string
		tweak    string // hex-encoded tweak
		expected string // hex-encoded expected output (tweak + encrypted IP)
	}{
		{
			key:      "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
			ip:       "0.0.0.0",
			tweak:    "21bd1834bc088cd2b4ecbe30b70898d7",
			expected: "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5",
		},
		{
			key:      "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
			ip:       "192.0.2.1",
			tweak:    "08e0c289bff23b7cb4ecbe30b70898d7",
			expected: "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a",
		},
		{
			key:      "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
			ip:       "2001:db8::1",
			tweak:    "21bd1834bc088cd2b4ecbe30b70898d7",
			expected: "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4",
		},
	}

	for i, test := range tests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Errorf("Test %d: Failed to decode key: %v", i, err)
			continue
		}

		tweak, err := hex.DecodeString(test.tweak)
		if err != nil {
			t.Errorf("Test %d: Failed to decode tweak: %v", i, err)
			continue
		}

		encrypted, err := EncryptIPNonDeterministicX(test.ip, key, tweak)
		if err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
			continue
		}

		// Convert encrypted data to hex string for comparison
		encryptedHex := hex.EncodeToString(encrypted)
		if encryptedHex != test.expected {
			t.Errorf("Test %d: Encryption failed: got %s, want %s", i, encryptedHex, test.expected)
			continue
		}

		decrypted, err := DecryptIPNonDeterministicX(encrypted, key)
		if err != nil {
			t.Errorf("Test %d: Decryption failed: %v", i, err)
			continue
		}

		if decrypted != test.ip {
			t.Errorf("Test %d: Decryption failed: got %s, want %s", i, decrypted, test.ip)
		}
	}

	// Test with random tweak
	key := make([]byte, KeySizeNDX)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	encrypted, err := EncryptIPNonDeterministicX("192.168.1.1", key, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt with random tweak: %v", err)
	}

	decrypted, err := DecryptIPNonDeterministicX(encrypted, key)
	if err != nil {
		t.Fatalf("Failed to decrypt with random tweak: %v", err)
	}

	if decrypted != "192.168.1.1" {
		t.Errorf("Random tweak test failed: got %s, want %s", decrypted, "192.168.1.1")
	}
}

// generateRandomIP generates a random IPv4 address.
func generateRandomIP(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// TestRandomIPs tests encryption and decryption with random IP addresses.
func TestRandomIPs(t *testing.T) {
	key := make([]byte, KeySizeDeterministic)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	const numTests = 100
	for i := 0; i < numTests; i++ {
		ip := generateRandomIP(t)
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			t.Errorf("Invalid IP address: %s", ip)
			continue
		}

		encrypted, err := EncryptIP(key, ipAddr)
		if err != nil {
			t.Errorf("EncryptIP failed for IP %s: %v", ip, err)
			continue
		}

		decrypted, err := DecryptIP(key, encrypted)
		if err != nil {
			t.Errorf("DecryptIP failed for encrypted IP %s: %v", encrypted, err)
			continue
		}

		if !decrypted.Equal(ipAddr) {
			t.Errorf("Decryption failed: got %s, want %s", decrypted, ipAddr)
		}
	}
}

func TestDecryptIPPfxAcceptsFourByteEncryptedIPv4(t *testing.T) {
	key, err := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	if err != nil {
		t.Fatalf("Failed to decode key: %v", err)
	}

	ip := net.ParseIP("192.0.2.1")
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}

	encrypted, err := EncryptIPPfx(ip, key)
	if err != nil {
		t.Fatalf("EncryptIPPfx failed: %v", err)
	}

	decrypted, err := DecryptIPPfx(encrypted.To4(), key)
	if err != nil {
		t.Fatalf("DecryptIPPfx failed for 4-byte encrypted IPv4: %v", err)
	}

	if !decrypted.Equal(ip) {
		t.Fatalf("Decryption failed: got %s, want %s", decrypted, ip)
	}
}

func TestEncryptIPNonDeterministicTo(t *testing.T) {
	key, _ := hex.DecodeString("1032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2")
	scratch := NewScratchPad()

	buf := make([]byte, NonDeterministicSize)
	encrypted, err := EncryptIPNonDeterministicTo(net.ParseIP("192.0.2.1"), key, tweak, buf, scratch)
	if err != nil {
		t.Fatalf("EncryptIPNonDeterministicTo failed: %v", err)
	}

	if &encrypted[0] != &buf[0] {
		t.Fatal("EncryptIPNonDeterministicTo did not reuse caller buffer")
	}

	if got := hex.EncodeToString(encrypted); got != "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad" {
		t.Fatalf("EncryptIPNonDeterministicTo mismatch: got %s", got)
	}

	if _, err := EncryptIPNonDeterministicTo(net.ParseIP("192.0.2.1"), key, tweak, make([]byte, NonDeterministicSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid encrypted parameter") {
		t.Fatalf("expected short-buffer error, got %v", err)
	}
}

func TestDecryptIPNonDeterministicTo(t *testing.T) {
	key, _ := hex.DecodeString("1032547698badcfeefcdab8967452301")
	ciphertext, _ := hex.DecodeString("21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad")
	scratch := NewScratchPad()

	buf := make([]byte, MaxIPSize)
	decrypted, err := DecryptIPNonDeterministicTo(ciphertext, key, buf, scratch)
	if err != nil {
		t.Fatalf("DecryptIPNonDeterministicTo failed: %v", err)
	}

	if &decrypted[0] != &buf[0] {
		t.Fatal("DecryptIPNonDeterministicTo did not reuse caller buffer")
	}

	if !decrypted.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("DecryptIPNonDeterministicTo mismatch: got %s", decrypted)
	}

	if _, err := DecryptIPNonDeterministicTo(ciphertext, key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid decrypted parameter") {
		t.Fatalf("expected short-buffer error, got %v", err)
	}
}

func TestEncryptIPPfxTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	scratch := NewScratchPad()

	ipv4Buf := make([]byte, MaxIPSize)
	encryptedIPv4, err := EncryptIPPfxTo(net.ParseIP("192.0.2.1"), key, ipv4Buf, scratch)
	if err != nil {
		t.Fatalf("EncryptIPPfxTo IPv4 failed: %v", err)
	}
	if &encryptedIPv4[0] != &ipv4Buf[0] {
		t.Fatal("EncryptIPPfxTo IPv4 did not reuse caller buffer")
	}
	if got := encryptedIPv4.String(); got != "100.115.72.131" {
		t.Fatalf("EncryptIPPfxTo IPv4 mismatch: got %s", got)
	}

	ipv6Buf := make([]byte, MaxIPSize)
	encryptedIPv6, err := EncryptIPPfxTo(net.ParseIP("2001:db8::1"), key, ipv6Buf, scratch)
	if err != nil {
		t.Fatalf("EncryptIPPfxTo IPv6 failed: %v", err)
	}
	if &encryptedIPv6[0] != &ipv6Buf[0] {
		t.Fatal("EncryptIPPfxTo IPv6 did not reuse caller buffer")
	}
	if got := encryptedIPv6.String(); got != "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88" {
		t.Fatalf("EncryptIPPfxTo IPv6 mismatch: got %s", got)
	}

	if _, err := EncryptIPPfxTo(net.ParseIP("192.0.2.1"), key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid encrypted parameter") {
		t.Fatalf("expected short IPv4 buffer error, got %v", err)
	}
	if _, err := EncryptIPPfxTo(net.ParseIP("2001:db8::1"), key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid encrypted parameter") {
		t.Fatalf("expected short IPv6 buffer error, got %v", err)
	}
}

func TestDecryptIPPfxTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	scratch := NewScratchPad()

	ipv4Buf := make([]byte, MaxIPSize)
	decryptedIPv4, err := DecryptIPPfxTo(net.ParseIP("100.115.72.131").To4(), key, ipv4Buf, scratch)
	if err != nil {
		t.Fatalf("DecryptIPPfxTo IPv4 failed: %v", err)
	}
	if &decryptedIPv4[0] != &ipv4Buf[0] {
		t.Fatal("DecryptIPPfxTo IPv4 did not reuse caller buffer")
	}
	if got := decryptedIPv4.String(); got != "192.0.2.1" {
		t.Fatalf("DecryptIPPfxTo IPv4 mismatch: got %s", got)
	}

	ipv6Buf := make([]byte, MaxIPSize)
	decryptedIPv6, err := DecryptIPPfxTo(net.ParseIP("c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"), key, ipv6Buf, scratch)
	if err != nil {
		t.Fatalf("DecryptIPPfxTo IPv6 failed: %v", err)
	}
	if &decryptedIPv6[0] != &ipv6Buf[0] {
		t.Fatal("DecryptIPPfxTo IPv6 did not reuse caller buffer")
	}
	if got := decryptedIPv6.String(); got != "2001:db8::1" {
		t.Fatalf("DecryptIPPfxTo IPv6 mismatch: got %s", got)
	}

	if _, err := DecryptIPPfxTo(net.ParseIP("100.115.72.131").To4(), key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid decrypted parameter") {
		t.Fatalf("expected short IPv4 buffer error, got %v", err)
	}
	if _, err := DecryptIPPfxTo(net.ParseIP("c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"), key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid decrypted parameter") {
		t.Fatalf("expected short IPv6 buffer error, got %v", err)
	}
}

func TestIPPfxScratchPadReuseAcrossCalls(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	scratch := NewScratchPad()

	encryptCases := []struct {
		ip       string
		expected string
	}{
		{ip: "192.0.2.1", expected: "100.115.72.131"},
		{ip: "2001:db8::1", expected: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"},
		{ip: "2001:db8::2", expected: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f8a"},
		{ip: "0.0.0.0", expected: "151.82.155.134"},
	}

	for _, tc := range encryptCases {
		buf := make([]byte, MaxIPSize)
		encrypted, err := EncryptIPPfxTo(net.ParseIP(tc.ip), key, buf, scratch)
		if err != nil {
			t.Fatalf("EncryptIPPfxTo(%s) failed: %v", tc.ip, err)
		}
		if &encrypted[0] != &buf[0] {
			t.Fatalf("EncryptIPPfxTo(%s) did not reuse caller buffer", tc.ip)
		}
		if got := encrypted.String(); got != tc.expected {
			t.Fatalf("EncryptIPPfxTo(%s) mismatch: got %s, want %s", tc.ip, got, tc.expected)
		}
	}

	decryptCases := []struct {
		ciphertext string
		expected   string
	}{
		{ciphertext: "100.115.72.131", expected: "192.0.2.1"},
		{ciphertext: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88", expected: "2001:db8::1"},
		{ciphertext: "151.82.155.134", expected: "0.0.0.0"},
	}

	for _, tc := range decryptCases {
		buf := make([]byte, MaxIPSize)
		decrypted, err := DecryptIPPfxTo(net.ParseIP(tc.ciphertext), key, buf, scratch)
		if err != nil {
			t.Fatalf("DecryptIPPfxTo(%s) failed: %v", tc.ciphertext, err)
		}
		if &decrypted[0] != &buf[0] {
			t.Fatalf("DecryptIPPfxTo(%s) did not reuse caller buffer", tc.ciphertext)
		}
		if got := decrypted.String(); got != tc.expected {
			t.Fatalf("DecryptIPPfxTo(%s) mismatch: got %s, want %s", tc.ciphertext, got, tc.expected)
		}
	}
}

func TestEncryptIPNonDeterministicXTo(t *testing.T) {
	key, _ := hex.DecodeString("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7cb4ecbe30b70898d7")
	scratch := NewScratchPad()

	buf := make([]byte, NonDeterministicXSize)
	encrypted, err := EncryptIPNonDeterministicXTo(net.ParseIP("192.0.2.1"), key, tweak, buf, scratch)
	if err != nil {
		t.Fatalf("EncryptIPNonDeterministicXTo failed: %v", err)
	}

	if &encrypted[0] != &buf[0] {
		t.Fatal("EncryptIPNonDeterministicXTo did not reuse caller buffer")
	}

	if got := hex.EncodeToString(encrypted); got != "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a" {
		t.Fatalf("EncryptIPNonDeterministicXTo mismatch: got %s", got)
	}

	if _, err := EncryptIPNonDeterministicXTo(net.ParseIP("192.0.2.1"), key, tweak, make([]byte, NonDeterministicXSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid encrypted parameter") {
		t.Fatalf("expected short-buffer error, got %v", err)
	}
}

func TestDecryptIPNonDeterministicXTo(t *testing.T) {
	key, _ := hex.DecodeString("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210")
	ciphertext, _ := hex.DecodeString("08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a")
	scratch := NewScratchPad()

	buf := make([]byte, MaxIPSize)
	decrypted, err := DecryptIPNonDeterministicXTo(ciphertext, key, buf, scratch)
	if err != nil {
		t.Fatalf("DecryptIPNonDeterministicXTo failed: %v", err)
	}

	if &decrypted[0] != &buf[0] {
		t.Fatal("DecryptIPNonDeterministicXTo did not reuse caller buffer")
	}

	if !decrypted.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("DecryptIPNonDeterministicXTo mismatch: got %s", decrypted)
	}

	if _, err := DecryptIPNonDeterministicXTo(ciphertext, key, make([]byte, MaxIPSize-1), scratch); err == nil || !strings.Contains(err.Error(), "invalid decrypted parameter") {
		t.Fatalf("expected short-buffer error, got %v", err)
	}
}

func TestIPNonDeterministicXScratchPadReuseAcrossCalls(t *testing.T) {
	key1, _ := hex.DecodeString("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210")
	key2, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b")
	tweak1, _ := hex.DecodeString("08e0c289bff23b7cb4ecbe30b70898d7")
	tweak2, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	scratch := NewScratchPad()

	encryptCases := []struct {
		ip       string
		key      []byte
		tweak    []byte
		expected string
	}{
		{
			ip:       "192.0.2.1",
			key:      key1,
			tweak:    tweak1,
			expected: "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a",
		},
		{
			ip:       "2001:db8::1",
			key:      key2,
			tweak:    tweak2,
			expected: "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4",
		},
	}

	ciphertexts := make([][]byte, 0, len(encryptCases))
	for _, tc := range encryptCases {
		buf := make([]byte, NonDeterministicXSize)
		encrypted, err := EncryptIPNonDeterministicXTo(net.ParseIP(tc.ip), tc.key, tc.tweak, buf, scratch)
		if err != nil {
			t.Fatalf("EncryptIPNonDeterministicXTo(%s) failed: %v", tc.ip, err)
		}
		if &encrypted[0] != &buf[0] {
			t.Fatalf("EncryptIPNonDeterministicXTo(%s) did not reuse caller buffer", tc.ip)
		}
		if got := hex.EncodeToString(encrypted); got != tc.expected {
			t.Fatalf("EncryptIPNonDeterministicXTo(%s) mismatch: got %s, want %s", tc.ip, got, tc.expected)
		}

		stableCopy := make([]byte, len(encrypted))
		copy(stableCopy, encrypted)
		ciphertexts = append(ciphertexts, stableCopy)
	}

	decryptCases := []struct {
		ciphertext []byte
		key        []byte
		expected   string
	}{
		{ciphertext: ciphertexts[0], key: key1, expected: "192.0.2.1"},
		{ciphertext: ciphertexts[1], key: key2, expected: "2001:db8::1"},
		{ciphertext: ciphertexts[0], key: key1, expected: "192.0.2.1"},
	}

	for _, tc := range decryptCases {
		buf := make([]byte, MaxIPSize)
		decrypted, err := DecryptIPNonDeterministicXTo(tc.ciphertext, tc.key, buf, scratch)
		if err != nil {
			t.Fatalf("DecryptIPNonDeterministicXTo failed: %v", err)
		}
		if &decrypted[0] != &buf[0] {
			t.Fatal("DecryptIPNonDeterministicXTo did not reuse caller buffer")
		}
		if got := decrypted.String(); got != tc.expected {
			t.Fatalf("DecryptIPNonDeterministicXTo mismatch: got %s, want %s", got, tc.expected)
		}
	}
}

// TestInvalidInputs tests error handling for invalid inputs.
func TestInvalidInputs(t *testing.T) {
	// Test invalid key length
	_, err := EncryptIP([]byte("short"), net.ParseIP("192.168.1.1"))
	if err == nil || !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("Expected key length error, got %v", err)
	}

	// Test invalid IP address
	_, err = EncryptIP(make([]byte, KeySizeDeterministic), net.ParseIP("not-an-ip"))
	if err == nil || !errors.Is(err, ErrInvalidIP) {
		t.Errorf("Expected invalid IP error, got %v", err)
	}

	// Test invalid ciphertext length for non-deterministic mode
	_, err = DecryptIPNonDeterministic([]byte("short"), make([]byte, KeySizeND))
	if err == nil || !strings.Contains(err.Error(), "invalid ciphertext length") {
		t.Errorf("Expected invalid ciphertext length error, got %v", err)
	}

	// Test invalid ciphertext length for non-deterministic X mode
	_, err = DecryptIPNonDeterministicX([]byte("short"), make([]byte, KeySizeNDX))
	if err == nil || !strings.Contains(err.Error(), "invalid ciphertext length") {
		t.Errorf("Expected invalid ciphertext length error, got %v", err)
	}
}

var (
	benchmarkIPSink     net.IP
	benchmarkBytesSink  []byte
	benchmarkStringSink string
)

type benchmarkVectorCase struct {
	name       string
	key        []byte
	tweak      []byte
	ip         net.IP
	ipString   string
	cipherIP   net.IP
	ciphertext []byte
}

func BenchmarkAllocations(b *testing.B) {
	deterministicCases := benchmarkCasesFromTestVectors(b, "ipcrypt-deterministic")
	ndCases := benchmarkCasesFromTestVectors(b, "ipcrypt-nd")
	ndxCases := benchmarkCasesFromTestVectors(b, "ipcrypt-ndx")
	pfxCases := benchmarkCasesFromTestVectors(b, "ipcrypt-pfx")

	b.Run("DeterministicEncrypt", func(b *testing.B) {
		for _, tc := range deterministicCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					ip, err := EncryptIP(tc.key, tc.ip)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = ip
				}
			})
		}
	})

	b.Run("DeterministicEncryptTo", func(b *testing.B) {
		for _, tc := range deterministicCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				if _, err := EncryptIPTo(tc.key, tc.ip, buf, scratch); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					ip, err := EncryptIPTo(tc.key, tc.ip, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = ip
				}
			})
		}
	})

	b.Run("DeterministicDecrypt", func(b *testing.B) {
		for _, tc := range deterministicCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					ip, err := DecryptIP(tc.key, tc.cipherIP)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = ip
				}
			})
		}
	})

	b.Run("DeterministicDecryptTo", func(b *testing.B) {
		for _, tc := range deterministicCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				if _, err := DecryptIPTo(tc.key, tc.cipherIP, buf, scratch); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					ip, err := DecryptIPTo(tc.key, tc.cipherIP, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = ip
				}
			})
		}
	})

	b.Run("NDEncrypt", func(b *testing.B) {
		for _, tc := range ndCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPNonDeterministic(tc.ipString, tc.key, tc.tweak)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkBytesSink = out
				}
			})
		}
	})

	b.Run("NDEncryptTo", func(b *testing.B) {
		for _, tc := range ndCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, NonDeterministicSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPNonDeterministicTo(tc.ip, tc.key, tc.tweak, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkBytesSink = out
				}
			})
		}
	})

	b.Run("NDDecrypt", func(b *testing.B) {
		for _, tc := range ndCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPNonDeterministic(tc.ciphertext, tc.key)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkStringSink = out
				}
			})
		}
	})

	b.Run("NDDecryptTo", func(b *testing.B) {
		for _, tc := range ndCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPNonDeterministicTo(tc.ciphertext, tc.key, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})

	b.Run("NDXEncrypt", func(b *testing.B) {
		for _, tc := range ndxCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPNonDeterministicX(tc.ipString, tc.key, tc.tweak)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkBytesSink = out
				}
			})
		}
	})

	b.Run("NDXEncryptTo", func(b *testing.B) {
		for _, tc := range ndxCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, NonDeterministicXSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPNonDeterministicXTo(tc.ip, tc.key, tc.tweak, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkBytesSink = out
				}
			})
		}
	})

	b.Run("NDXDecrypt", func(b *testing.B) {
		for _, tc := range ndxCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPNonDeterministicX(tc.ciphertext, tc.key)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkStringSink = out
				}
			})
		}
	})

	b.Run("NDXDecryptTo", func(b *testing.B) {
		for _, tc := range ndxCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPNonDeterministicXTo(tc.ciphertext, tc.key, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})

	b.Run("PFXEncrypt", func(b *testing.B) {
		for _, tc := range pfxCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPPfx(tc.ip, tc.key)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})

	b.Run("PFXEncryptTo", func(b *testing.B) {
		for _, tc := range pfxCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := EncryptIPPfxTo(tc.ip, tc.key, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})

	b.Run("PFXDecrypt", func(b *testing.B) {
		for _, tc := range pfxCases {
			b.Run(tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPPfx(tc.cipherIP, tc.key)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})

	b.Run("PFXDecryptTo", func(b *testing.B) {
		for _, tc := range pfxCases {
			b.Run(tc.name, func(b *testing.B) {
				buf := make([]byte, MaxIPSize)
				scratch := NewScratchPad()
				b.ReportAllocs()
				for b.Loop() {
					out, err := DecryptIPPfxTo(tc.cipherIP, tc.key, buf, scratch)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIPSink = out
				}
			})
		}
	})
}

func benchmarkCasesFromTestVectors(b *testing.B, variant string) []benchmarkVectorCase {
	b.Helper()

	var cases []benchmarkVectorCase
	haveIPv4 := false
	haveIPv6 := false

	for _, tv := range testVectors {
		if tv.variant != variant {
			continue
		}

		addr, err := netip.ParseAddr(tv.ip)
		if err != nil {
			b.Fatalf("invalid benchmark IP in test vector: %s", tv.ip)
		}

		isIPv4 := addr.Is4()
		if isIPv4 && haveIPv4 {
			continue
		}
		if !isIPv4 && haveIPv6 {
			continue
		}

		var ip net.IP
		if isIPv4 {
			temp := addr.As4()
			ip = temp[:]
		} else {
			temp := addr.As16()
			ip = temp[:]
		}

		key, err := hex.DecodeString(tv.key)
		if err != nil {
			b.Fatal(err)
		}

		tc := benchmarkVectorCase{
			name:     ipFamilyName(ip),
			key:      key,
			ip:       ip,
			ipString: tv.ip,
		}

		if tv.tweak != "" {
			tc.tweak, err = hex.DecodeString(tv.tweak)
			if err != nil {
				b.Fatal(err)
			}
		}

		switch variant {
		case "ipcrypt-deterministic", "ipcrypt-pfx":
			tc.cipherIP = net.ParseIP(tv.output)
			if tc.cipherIP == nil {
				b.Fatalf("invalid benchmark ciphertext IP in test vector: %s", tv.output)
			}
		case "ipcrypt-nd", "ipcrypt-ndx":
			tc.ciphertext, err = hex.DecodeString(tv.output)
			if err != nil {
				b.Fatal(err)
			}
		default:
			b.Fatalf("unsupported benchmark variant: %s", variant)
		}

		cases = append(cases, tc)
		if isIPv4 {
			haveIPv4 = true
		} else {
			haveIPv6 = true
		}
	}

	if len(cases) == 0 {
		b.Fatalf("no benchmark cases found for variant %s", variant)
	}
	return cases
}

func ipFamilyName(ip net.IP) string {
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}
