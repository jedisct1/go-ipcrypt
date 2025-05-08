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
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Compare output
			var got string
			switch tv.variant {
			case "ipcrypt-deterministic":
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
	rand.Read(key)

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
	rand.Read(key)

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
	rand.Read(b)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// TestRandomIPs tests encryption and decryption with random IP addresses.
func TestRandomIPs(t *testing.T) {
	key := make([]byte, KeySizeDeterministic)
	rand.Read(key)

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
