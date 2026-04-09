// Package ipcrypt contains tests for the ipcrypt package.
package ipcrypt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
				encrypted, err = EncryptIP(key, ip)
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
				encrypted, err = EncryptIPPfx(ip, key)
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
			var decryptedStr string
			switch tv.variant {
			case "ipcrypt-deterministic":
				decrypted, err = DecryptIP(key, net.IP(encrypted))
			case "ipcrypt-nd":
				decryptedStr, err = DecryptIPNonDeterministic(encrypted, key)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}
				decrypted = net.ParseIP(decryptedStr)
			case "ipcrypt-ndx":
				decryptedStr, err = DecryptIPNonDeterministicX(encrypted, key)
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

// TestEncryptIPTo tests the EncryptIPTo destination-buffer variant.
func TestEncryptIPTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("0.0.0.0")
	expected := "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, 16)
		result, err := EncryptIPTo(dst, key, ip)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != expected {
			t.Errorf("got %s, want %s", result, expected)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := EncryptIPTo(nil, key, ip)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != expected {
			t.Errorf("got %s, want %s", result, expected)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		dst := make([]byte, 4)
		result, err := EncryptIPTo(dst, key, ip)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != expected {
			t.Errorf("got %s, want %s", result, expected)
		}
	})
}

// TestDecryptIPTo tests the DecryptIPTo destination-buffer variant.
func TestDecryptIPTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("0.0.0.0")
	encrypted, _ := EncryptIP(key, ip)

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, 16)
		result, err := DecryptIPTo(dst, key, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(ip) {
			t.Errorf("got %s, want %s", result, ip)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := DecryptIPTo(nil, key, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(ip) {
			t.Errorf("got %s, want %s", result, ip)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		result, err := DecryptIPTo(make([]byte, 4), key, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(ip) {
			t.Errorf("got %s, want %s", result, ip)
		}
	})
}

// TestEncryptIPNonDeterministicTo tests the ND To variant.
func TestEncryptIPNonDeterministicTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	expected := "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, TweakSize+16)
		result, err := EncryptIPNonDeterministicTo(dst, "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := EncryptIPNonDeterministicTo(nil, "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		result, err := EncryptIPNonDeterministicTo(make([]byte, 4), "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
	})
}

// TestDecryptIPNonDeterministicTo tests the ND decrypt To variant.
func TestDecryptIPNonDeterministicTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ciphertext, _ := hex.DecodeString("08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16")

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, 16)
		result, err := DecryptIPNonDeterministicTo(dst, ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := DecryptIPNonDeterministicTo(nil, ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		result, err := DecryptIPNonDeterministicTo(make([]byte, 4), ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
	})
}

// TestEncryptIPNonDeterministicXTo tests the NDX encrypt To variant.
func TestEncryptIPNonDeterministicXTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	expected := "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, TweakSizeX+16)
		result, err := EncryptIPNonDeterministicXTo(dst, "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := EncryptIPNonDeterministicXTo(nil, "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		result, err := EncryptIPNonDeterministicXTo(make([]byte, 4), "0.0.0.0", key, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(result) != expected {
			t.Errorf("got %s, want %s", hex.EncodeToString(result), expected)
		}
	})
}

// TestDecryptIPNonDeterministicXTo tests the NDX decrypt To variant.
func TestDecryptIPNonDeterministicXTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ciphertext, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5")

	t.Run("pre-allocated", func(t *testing.T) {
		dst := make([]byte, 16)
		result, err := DecryptIPNonDeterministicXTo(dst, ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
		if &result[0] != &dst[0] {
			t.Error("result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		result, err := DecryptIPNonDeterministicXTo(nil, ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		result, err := DecryptIPNonDeterministicXTo(make([]byte, 4), ciphertext, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.IPv4(0, 0, 0, 0)) {
			t.Errorf("got %s, want 0.0.0.0", result)
		}
	})
}

// TestEncryptIPPfxTo tests the PFX encrypt To variant.
func TestEncryptIPPfxTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")

	t.Run("ipv4/pre-allocated", func(t *testing.T) {
		ip := net.ParseIP("192.0.2.1")
		dst := make([]byte, 16)
		result, err := EncryptIPPfxTo(dst, ip, key)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != "100.115.72.131" {
			t.Errorf("got %s, want 100.115.72.131", result)
		}
		// IPv4 returns dst[12:16]
		if &result[0] != &dst[12] {
			t.Error("IPv4 result does not point into dst[12:]")
		}
	})

	t.Run("ipv6/pre-allocated", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")
		dst := make([]byte, 16)
		result, err := EncryptIPPfxTo(dst, ip, key)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88" {
			t.Errorf("got %s, want c180:5dd4:2587:3524:30ab:fa65:6ab6:f88", result)
		}
		if &result[0] != &dst[0] {
			t.Error("IPv6 result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		ip := net.ParseIP("192.0.2.1")
		result, err := EncryptIPPfxTo(nil, ip, key)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != "100.115.72.131" {
			t.Errorf("got %s, want 100.115.72.131", result)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		ip := net.ParseIP("192.0.2.1")
		result, err := EncryptIPPfxTo(make([]byte, 4), ip, key)
		if err != nil {
			t.Fatal(err)
		}
		if result.String() != "100.115.72.131" {
			t.Errorf("got %s, want 100.115.72.131", result)
		}
	})
}

// TestDecryptIPPfxTo tests the PFX decrypt To variant.
func TestDecryptIPPfxTo(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")

	t.Run("ipv4/pre-allocated", func(t *testing.T) {
		encrypted := net.ParseIP("100.115.72.131")
		dst := make([]byte, 16)
		result, err := DecryptIPPfxTo(dst, encrypted, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.ParseIP("192.0.2.1")) {
			t.Errorf("got %s, want 192.0.2.1", result)
		}
		if &result[0] != &dst[12] {
			t.Error("IPv4 result does not point into dst[12:]")
		}
	})

	t.Run("ipv6/pre-allocated", func(t *testing.T) {
		encrypted := net.ParseIP("c180:5dd4:2587:3524:30ab:fa65:6ab6:f88")
		dst := make([]byte, 16)
		result, err := DecryptIPPfxTo(dst, encrypted, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.ParseIP("2001:db8::1")) {
			t.Errorf("got %s, want 2001:db8::1", result)
		}
		if &result[0] != &dst[0] {
			t.Error("IPv6 result does not point into dst")
		}
	})

	t.Run("nil-dst", func(t *testing.T) {
		encrypted := net.ParseIP("100.115.72.131")
		result, err := DecryptIPPfxTo(nil, encrypted, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.ParseIP("192.0.2.1")) {
			t.Errorf("got %s, want 192.0.2.1", result)
		}
	})

	t.Run("short-dst", func(t *testing.T) {
		encrypted := net.ParseIP("100.115.72.131")
		result, err := DecryptIPPfxTo(make([]byte, 4), encrypted, key)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Equal(net.ParseIP("192.0.2.1")) {
			t.Errorf("got %s, want 192.0.2.1", result)
		}
	})
}

// Allocation benchmarks

func BenchmarkEncryptIP(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIP(key, ip)
	}
}

func BenchmarkEncryptIPTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	dst := make([]byte, 16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPTo(dst, key, ip)
	}
}

func BenchmarkDecryptIP(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	encrypted, _ := EncryptIP(key, ip)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIP(key, encrypted)
	}
}

func BenchmarkDecryptIPTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	encrypted, _ := EncryptIP(key, ip)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPTo(dst, key, encrypted)
	}
}

func BenchmarkEncryptIPNonDeterministic(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPNonDeterministic("192.0.2.1", key, tweak)
	}
}

func BenchmarkEncryptIPNonDeterministicTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	dst := make([]byte, TweakSize+16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPNonDeterministicTo(dst, "192.0.2.1", key, tweak)
	}
}

func BenchmarkDecryptIPNonDeterministic(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	ct, _ := EncryptIPNonDeterministic("192.0.2.1", key, tweak)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPNonDeterministic(ct, key)
	}
}

func BenchmarkDecryptIPNonDeterministicTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	ct, _ := EncryptIPNonDeterministic("192.0.2.1", key, tweak)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPNonDeterministicTo(dst, ct, key)
	}
}

func BenchmarkEncryptIPNonDeterministicX(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPNonDeterministicX("192.0.2.1", key, tweak)
	}
}

func BenchmarkEncryptIPNonDeterministicXTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	dst := make([]byte, TweakSizeX+16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPNonDeterministicXTo(dst, "192.0.2.1", key, tweak)
	}
}

func BenchmarkDecryptIPNonDeterministicX(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	ct, _ := EncryptIPNonDeterministicX("192.0.2.1", key, tweak)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPNonDeterministicX(ct, key)
	}
}

func BenchmarkDecryptIPNonDeterministicXTo(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	ct, _ := EncryptIPNonDeterministicX("192.0.2.1", key, tweak)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPNonDeterministicXTo(dst, ct, key)
	}
}

func BenchmarkEncryptIPPfx_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPPfx(ip, key)
	}
}

func BenchmarkEncryptIPPfxTo_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	dst := make([]byte, 16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPPfxTo(dst, ip, key)
	}
}

func BenchmarkDecryptIPPfx_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	encrypted, _ := EncryptIPPfx(ip, key)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPPfx(encrypted, key)
	}
}

func BenchmarkDecryptIPPfxTo_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	encrypted, _ := EncryptIPPfx(ip, key)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPPfxTo(dst, encrypted, key)
	}
}

func BenchmarkEncryptIPPfx_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPPfx(ip, key)
	}
}

func BenchmarkEncryptIPPfxTo_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	dst := make([]byte, 16)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptIPPfxTo(dst, ip, key)
	}
}

func BenchmarkDecryptIPPfx_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	encrypted, _ := EncryptIPPfx(ip, key)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPPfx(encrypted, key)
	}
}

func BenchmarkDecryptIPPfxTo_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	encrypted, _ := EncryptIPPfx(ip, key)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptIPPfxTo(dst, encrypted, key)
	}
}
