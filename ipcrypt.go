// Package ipcrypt implements IP address encryption and obfuscation methods.
// It provides four encryption modes:
//   - ipcrypt-deterministic: A deterministic mode where the same input always produces the same output
//   - ipcrypt-nd: A non-deterministic mode that uses an 8-byte tweak
//   - ipcrypt-ndx: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak
//   - ipcrypt-pfx: A prefix-preserving mode that maintains the original IP format (IPv4 or IPv6)
//
// For non-deterministic modes, passing nil as the tweak parameter will automatically generate a random tweak.
package ipcrypt

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
)

// Key sizes for different encryption modes
const (
	KeySizeDeterministic = 16 // Size in bytes of the key for ipcrypt-deterministic mode
	KeySizeND            = 16 // Size in bytes of the key for ipcrypt-nd mode
	KeySizeNDX           = 32 // Size in bytes of the key for ipcrypt-ndx mode
)

// Tweak sizes for different encryption modes
const (
	TweakSize  = 8  // Size in bytes of the tweak for ipcrypt-nd mode
	TweakSizeX = 16 // Size in bytes of the tweak for ipcrypt-ndx mode
)

// Max length of an encrypted or decrypted IP address
const (
	MaxIPLength           = 16 // Maximum length of an encrypted IP address in bytes
	NonDeterministicSize  = TweakSize + MaxIPLength
	NonDeterministicXSize = TweakSizeX + MaxIPLength
)

var (
	pfxIPv4PaddedPrefix = [MaxIPLength]byte{3: 0x01, 14: 0xFF, 15: 0xFF}
	pfxIPv6PaddedPrefix = [MaxIPLength]byte{15: 0x01}
)

// Error definitions for the package
var (
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrInvalidIP      = errors.New("invalid IP address")
	ErrInvalidTweak   = errors.New("invalid tweak size")
)

// ScratchPad enables reuse of byte slices during encryption and decryption operations to avoid allocations
type ScratchPad struct {
	Scratch1 []byte
	Scratch2 []byte
	Scratch3 []byte
	Scratch4 []byte
}

// init initializes the scratchpad with empty byte slices of the appropriate size if necessary
func (s *ScratchPad) init() {
	if s.Scratch1 == nil {
		s.Scratch1 = make([]byte, MaxIPLength)
	}
	if s.Scratch2 == nil {
		s.Scratch2 = make([]byte, MaxIPLength)
	}
	if s.Scratch3 == nil {
		s.Scratch3 = make([]byte, MaxIPLength)
	}
	if s.Scratch4 == nil {
		s.Scratch4 = make([]byte, MaxIPLength)
	}
}

func getScratchPad(scratch *ScratchPad) *ScratchPad {
	if scratch == nil {
		return NewScratchPad()
	}
	scratch.init()
	return scratch
}

func NewScratchPad() *ScratchPad {
	s := ScratchPad{}
	s.init()
	return &s
}

// Utility functions

// validateKey checks if the key length matches the expected size
func validateKey(key []byte, expectedSize int) error {
	if len(key) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidKeySize, len(key), expectedSize)
	}
	return nil
}

// validateIP ensures the IP address is valid and can be converted to 16-byte form
func validateIP(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, ErrInvalidIP
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, ErrInvalidIP
	}
	return ip16, nil
}

// validateTweak checks if the tweak length matches the expected size
func validateTweak(tweak []byte, expectedSize int) error {
	if len(tweak) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidTweak, len(tweak), expectedSize)
	}
	return nil
}

// xorBytesTo performs XOR operation on two byte slices of equal length.
// The to parameter must be a byte slice of equal length to a and b.
func xorBytesTo(a, b, to []byte) []byte {
	if len(a) != len(b) || len(to) != len(b) {
		return nil
	}
	subtle.XORBytes(to, a, b)
	return to
}

// xorBytes performs XOR operation on two byte slices of equal length.
func xorBytes(a, b []byte) []byte {
	to := make([]byte, len(a))
	return xorBytesTo(a, b, to)
}

func validateOutputLength(buf []byte, expectedSize int, parameterName string) error {
	if len(buf) < expectedSize {
		return fmt.Errorf("invalid %s parameter: got %d bytes, want at least %d bytes", parameterName, len(buf), expectedSize)
	}
	return nil
}

// Deterministic mode functions

// EncryptIP encrypts an IP address using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// The encrypted parameter must be a byte slice of minimum MaxIPLength bytes long
// Returns the encrypted IP address as a net.IP.
func EncryptIPTo(key []byte, ip net.IP, encrypted []byte) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, MaxIPLength, "encrypted"); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	block.Encrypt(encrypted, ipBytes)

	return net.IP(encrypted), nil
}

// EncryptIP encrypts an IP address using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the encrypted IP address as a net.IP.
func EncryptIP(key []byte, ip net.IP) (net.IP, error) {
	encrypted := make([]byte, 16)
	return EncryptIPTo(key, ip, encrypted)
}

// DecryptIP decrypts an IP address that was encrypted using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long
// Returns the decrypted IP address as a net.IP.
func DecryptIPTo(key []byte, encrypted net.IP, decrypted []byte) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	if err := validateOutputLength(decrypted, MaxIPLength, "decrypted"); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	block.Decrypt(decrypted, ipBytes)

	return net.IP(decrypted), nil
}

// DecryptIP decrypts an IP address that was encrypted using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIP(key []byte, encrypted net.IP) (net.IP, error) {
	decrypted := make([]byte, 16)
	return DecryptIPTo(key, encrypted, decrypted)
}

// Non-deterministic mode functions

// EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// The encrypted parameter must be a byte slice of minimum NonDeterministicSize bytes long.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicTo(ip string, key []byte, tweak []byte, encrypted []byte) ([]byte, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, NonDeterministicSize, "encrypted"); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	var t []byte
	if tweak == nil {
		t = encrypted[:TweakSize]
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSize); err != nil {
			return nil, err
		}
		t = tweak
		copy(encrypted[:TweakSize], t)
	}

	ciphertext, err := KiasuBCEncrypt(key, t, ipBytes)
	if err != nil {
		return nil, err
	}

	copy(encrypted[TweakSize:], ciphertext)
	return encrypted[:NonDeterministicSize], nil
}

// EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error) {
	encrypted := make([]byte, NonDeterministicSize)
	return EncryptIPNonDeterministicTo(ip, key, tweak, encrypted)
}

// DecryptIPNonDeterministicTo decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIPNonDeterministicTo(ciphertext []byte, key []byte, decrypted []byte) (net.IP, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}

	if len(ciphertext) != NonDeterministicSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), NonDeterministicSize)
	}

	if err := validateOutputLength(decrypted, MaxIPLength, "decrypted"); err != nil {
		return nil, err
	}

	tweak := ciphertext[:TweakSize]
	encryptedIP := ciphertext[TweakSize:]

	plainIP, err := KiasuBCDecrypt(key, tweak, encryptedIP)
	if err != nil {
		return nil, err
	}

	copy(decrypted, plainIP)
	return net.IP(decrypted[:MaxIPLength]), nil
}

// DecryptIPNonDeterministic decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error) {
	decrypted := make([]byte, MaxIPLength)
	ip, err := DecryptIPNonDeterministicTo(ciphertext, key, decrypted)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}

// Prefix-preserving mode functions

// EncryptIPPfxTo encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// The encrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the encrypted IP address in 16-byte form.
func EncryptIPPfxTo(ip net.IP, key []byte, encrypted []byte) (net.IP, error) {
	return EncryptIPPfxToScratch(ip, key, encrypted, nil)
}

// EncryptIPPfxToScratch encrypts an IP address using ipcrypt-pfx mode using the provided scratchpad to avoid allocations.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// The encrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the encrypted IP address in 16-byte form.
func EncryptIPPfxToScratch(ip net.IP, key []byte, encrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32 bytes", ErrInvalidKeySize, len(key))
	}

	// Split the key into two AES-128 keys
	k1 := key[:16]
	k2 := key[16:32]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	// Convert IP to 16-byte representation
	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	// Create AES cipher objects
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	// Determine if this is IPv4
	isIPv4 := ip.To4() != nil
	if err := validateOutputLength(encrypted, MaxIPLength, "encrypted"); err != nil {
		return nil, err
	}
	scratch = getScratchPad(scratch)

	encrypted = encrypted[:MaxIPLength]

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		// Copy the IPv4-mapped prefix
		copy(encrypted[:12], ipBytes[:12])
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := scratch.Scratch1[:MaxIPLength]
	if isIPv4 {
		copy(paddedPrefix, pfxIPv4PaddedPrefix[:])
	} else {
		copy(paddedPrefix, pfxIPv6PaddedPrefix[:])
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := scratch.Scratch2[:MaxIPLength]
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := scratch.Scratch3[:MaxIPLength]
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytesTo(e1, e2, scratch.Scratch4[:MaxIPLength])
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the original IP
		currentBitPos := 127 - prefixLenBits
		originalBit := getBit(ipBytes, currentBitPos)

		// Set the bit in the encrypted result
		setBit(encrypted, currentBitPos, cipherBit^originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from ipBytes
		shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	return net.IP(encrypted), nil
}

// EncryptIPPfx encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the encrypted IP address maintaining the original format (IPv4 or IPv6).
func EncryptIPPfx(ip net.IP, key []byte) (net.IP, error) {
	encrypted := make([]byte, MaxIPLength)
	return EncryptIPPfxTo(ip, key, encrypted)
}

// DecryptIPPfxTo decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the decrypted IP address
func DecryptIPPfxTo(encryptedIP net.IP, key []byte, decrypted []byte) (net.IP, error) {
	return DecryptIPPfxToScratch(encryptedIP, key, decrypted, nil)
}

// DecryptIPPfxToScratch decrypts an IP address that was encrypted using ipcrypt-pfx mode using the provided scratchpad to avoid allocations.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the decrypted IP address
func DecryptIPPfxToScratch(encryptedIP net.IP, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32 bytes", ErrInvalidKeySize, len(key))
	}

	// Split the key into two AES-128 keys
	k1 := key[:16]
	k2 := key[16:32]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	// Keep IPv4 ciphertexts in their IPv4 code path, but normalize them to
	// the 16-byte IPv4-mapped form before the bitwise decryption loop.
	isIPv4 := encryptedIP.To4() != nil
	if err := validateOutputLength(decrypted, MaxIPLength, "decrypted"); err != nil {
		return nil, err
	}
	scratch = getScratchPad(scratch)

	encryptedBytes, err := validateIP(encryptedIP)
	if err != nil {
		return nil, err
	}

	// Create AES cipher objects
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	decrypted = decrypted[:MaxIPLength]

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		// Copy the IPv4-mapped prefix
		copy(decrypted[:12], encryptedBytes[:12])
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := scratch.Scratch1[:MaxIPLength]
	if isIPv4 {
		copy(paddedPrefix, pfxIPv4PaddedPrefix[:])
	} else {
		copy(paddedPrefix, pfxIPv6PaddedPrefix[:])
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := scratch.Scratch2[:MaxIPLength]
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := scratch.Scratch3[:MaxIPLength]
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytesTo(e1, e2, scratch.Scratch4[:MaxIPLength])
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the encrypted IP
		currentBitPos := 127 - prefixLenBits
		encryptedBit := getBit(encryptedBytes, currentBitPos)
		originalBit := cipherBit ^ encryptedBit

		// Set the bit in the decrypted result
		setBit(decrypted, currentBitPos, originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from decrypted
		shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	return net.IP(decrypted), nil
}

// DecryptIPPfx decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the decrypted IP address.
func DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error) {
	decrypted := make([]byte, MaxIPLength)
	return DecryptIPPfxTo(encryptedIP, key, decrypted)
}

// Helper functions for bit manipulation

// getBit extracts bit at position from 16-byte array
// position: 0 = LSB of byte 15, 127 = MSB of byte 0
func getBit(data []byte, position int) byte {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	return (data[byteIndex] >> bitIndex) & 1
}

// setBit sets bit at position in 16-byte array
// position: 0 = LSB of byte 15, 127 = MSB of byte 0
func setBit(data []byte, position int, value byte) {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	if value != 0 {
		data[byteIndex] |= 1 << bitIndex
	} else {
		data[byteIndex] &^= 1 << bitIndex
	}
}

// shiftLeftOneBit shifts a 16-byte array one bit to the left in place.
// The most significant bit is lost, and a zero bit is shifted in from the right.
func shiftLeftOneBit(data []byte) {
	if len(data) != 16 {
		return
	}

	carry := byte(0)

	// Process from least significant byte (byte 15) to most significant (byte 0)
	for i := 15; i >= 0; i-- {
		nextCarry := (data[i] >> 7) & 1
		// Current byte shifted left by 1, with carry from previous byte
		data[i] = (data[i] << 1) | carry
		// Extract the bit that will be carried to the next byte
		carry = nextCarry
	}
}

// Extended non-deterministic mode functions

// EncryptIPNonDeterministicXTo encrypts an IP address using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// The encrypted parameter must be a byte slice of minimum NonDeterministicXSize bytes long.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicXTo(ip string, key []byte, tweak []byte, encrypted []byte) ([]byte, error) {
	return EncryptIPNonDeterministicXToScratch(ip, key, tweak, encrypted, nil)
}

// EncryptIPNonDeterministicXToScratch encrypts an IP address using ipcrypt-ndx mode using the provided scratchpad to avoid allocations.
// The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// The encrypted parameter must be a byte slice of minimum NonDeterministicXSize bytes long.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicXToScratch(ip string, key []byte, tweak []byte, encrypted []byte, scratch *ScratchPad) ([]byte, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, NonDeterministicXSize, "encrypted"); err != nil {
		return nil, err
	}
	scratch = getScratchPad(scratch)

	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := aes.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	var t []byte
	if tweak == nil {
		t = encrypted[:TweakSizeX]
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSizeX); err != nil {
			return nil, err
		}
		t = tweak
		copy(encrypted[:TweakSizeX], t)
	}

	encryptedTweak := scratch.Scratch1[:MaxIPLength]
	block2.Encrypt(encryptedTweak, t)

	xoredIP := xorBytesTo(ipBytes, encryptedTweak, scratch.Scratch2[:MaxIPLength])
	if xoredIP == nil {
		return nil, errors.New("XOR operation failed")
	}

	block1.Encrypt(encrypted[TweakSizeX:], xoredIP)

	finalEncrypted := xorBytesTo(encrypted[TweakSizeX:], encryptedTweak, scratch.Scratch3[:MaxIPLength])
	if finalEncrypted == nil {
		return nil, errors.New("XOR operation failed")
	}

	copy(encrypted[TweakSizeX:], finalEncrypted)
	return encrypted[:NonDeterministicXSize], nil
}

// EncryptIPNonDeterministicX encrypts an IP address using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicX(ip string, key []byte, tweak []byte) ([]byte, error) {
	encrypted := make([]byte, NonDeterministicXSize)
	return EncryptIPNonDeterministicXTo(ip, key, tweak, encrypted)
}

// DecryptIPNonDeterministicXTo decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIPNonDeterministicXTo(ciphertext []byte, key []byte, decrypted []byte) (net.IP, error) {
	return DecryptIPNonDeterministicXToScratch(ciphertext, key, decrypted, nil)
}

// DecryptIPNonDeterministicXToScratch decrypts an IP address that was encrypted using ipcrypt-ndx mode using the provided scratchpad to avoid allocations.
// The key must be exactly KeySizeNDX bytes long.
// The decrypted parameter must be a byte slice of minimum MaxIPLength bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIPNonDeterministicXToScratch(ciphertext []byte, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	if len(ciphertext) != NonDeterministicXSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), NonDeterministicXSize)
	}

	if err := validateOutputLength(decrypted, MaxIPLength, "decrypted"); err != nil {
		return nil, err
	}
	scratch = getScratchPad(scratch)

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := aes.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	tweak := ciphertext[:TweakSizeX]
	encryptedIP := ciphertext[TweakSizeX:]

	encryptedTweak := scratch.Scratch1[:MaxIPLength]
	block2.Encrypt(encryptedTweak, tweak)

	xoredIP := xorBytesTo(encryptedIP, encryptedTweak, scratch.Scratch2[:MaxIPLength])
	if xoredIP == nil {
		return nil, errors.New("XOR operation failed")
	}

	block1.Decrypt(decrypted, xoredIP)

	finalDecrypted := xorBytesTo(decrypted, encryptedTweak, scratch.Scratch3[:MaxIPLength])
	if finalDecrypted == nil {
		return nil, errors.New("XOR operation failed")
	}

	copy(decrypted, finalDecrypted)
	return net.IP(decrypted[:MaxIPLength]), nil
}

// DecryptIPNonDeterministicX decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error) {
	decrypted := make([]byte, MaxIPLength)
	ip, err := DecryptIPNonDeterministicXTo(ciphertext, key, decrypted)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}
