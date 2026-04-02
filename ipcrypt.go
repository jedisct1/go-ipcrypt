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
	"crypto/cipher"
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
	KeySizePFX           = 32 // Size in bytes of the key for ipcrypt-pfx mode
)

// Tweak sizes for different encryption modes
const (
	TweakSize  = 8  // Size in bytes of the tweak for ipcrypt-nd mode
	TweakSizeX = 16 // Size in bytes of the tweak for ipcrypt-ndx mode
)

// Max length of an encrypted or decrypted IP address
const (
	MaxScratchSize        = net.IPv6len // Maximum scratch buffer size in bytes
	NonDeterministicSize  = TweakSize + net.IPv6len
	NonDeterministicXSize = TweakSizeX + net.IPv6len
)

var (
	pfxIPv4PaddedPrefix = [net.IPv6len]byte{3: 0x01, 14: 0xFF, 15: 0xFF}
	pfxIPv6PaddedPrefix = [net.IPv6len]byte{15: 0x01}
	ipv4MappedPrefix    = [12]byte{10: 0xFF, 11: 0xFF}
)

// Error definitions for the package
var (
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrInvalidIP      = errors.New("invalid IP address")
	ErrInvalidTweak   = errors.New("invalid tweak size")
)

// ScratchPad enables reuse of byte slices during encryption and decryption operations to avoid allocations
type ScratchPad struct {
	scratch1 [MaxScratchSize]byte
	scratch2 [MaxScratchSize]byte
	scratch3 [MaxScratchSize]byte
	scratch4 [MaxScratchSize]byte

	keySlot1 [aes.BlockSize]byte
	keySlot2 [aes.BlockSize]byte

	blockSlot1 cipher.Block
	blockSlot2 cipher.Block

	// The saved key slots start as all-zero bytes, so an all-zero key would be
	// indistinguishable from the zero value without an explicit readiness bit.
	blockSlot1Ready bool
	blockSlot2Ready bool

	roundKeys1 [11][16]byte
	roundKeys2 [11][16]byte
	// The cached round key arrays also have a meaningful all-zero zero value, so
	// a separate readiness bit is required before relying on key equality.
	roundKeys1Ready bool
	roundKeys2Ready bool
}

func (s *ScratchPad) getAESBlock(slot int, key []byte) (cipher.Block, error) {
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidKeySize, len(key), aes.BlockSize)
	}

	switch slot {
	case 1:
		if s.blockSlot1Ready && subtle.ConstantTimeCompare(s.keySlot1[:], key) == 1 {
			return s.blockSlot1, nil
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		copy(s.keySlot1[:], key)
		s.blockSlot1 = block
		s.blockSlot1Ready = true
		return block, nil
	case 2:
		if s.blockSlot2Ready && subtle.ConstantTimeCompare(s.keySlot2[:], key) == 1 {
			return s.blockSlot2, nil
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		copy(s.keySlot2[:], key)
		s.blockSlot2 = block
		s.blockSlot2Ready = true
		return block, nil
	default:
		return nil, errors.New("invalid AES block slot")
	}
}

func (s *ScratchPad) getRoundKeys(slot int, key []byte) *[11][16]byte {
	switch slot {
	case 1:
		if !s.roundKeys1Ready || subtle.ConstantTimeCompare(s.keySlot1[:], key) != 1 {
			expandKeyTo(key, &s.roundKeys1)
			copy(s.keySlot1[:], key)
			s.roundKeys1Ready = true
		}
		return &s.roundKeys1
	case 2:
		if !s.roundKeys2Ready || subtle.ConstantTimeCompare(s.keySlot2[:], key) != 1 {
			expandKeyTo(key, &s.roundKeys2)
			copy(s.keySlot2[:], key)
			s.roundKeys2Ready = true
		}
		return &s.roundKeys2
	default:
		panic("invalid round key slot")
	}
}

func NewScratchPad() *ScratchPad {
	return &ScratchPad{}
}

// Utility functions

// validateKey checks if the key length matches the expected size
func validateKey(key []byte, expectedSize int) error {
	if len(key) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidKeySize, len(key), expectedSize)
	}
	return nil
}

// validateIPTo ensures the IP address is valid and writes its 16-byte form to dst.
func validateIPTo(ip net.IP, dst []byte) error {
	if ip == nil {
		return ErrInvalidIP
	}

	if len(ip) == net.IPv6len {
		copy(dst, ip)
		return nil
	}

	if len(ip) == net.IPv4len {
		copy(dst[:len(ipv4MappedPrefix)], ipv4MappedPrefix[:])
		copy(dst[len(ipv4MappedPrefix):], ip)
		return nil
	}

	return ErrInvalidIP
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
	if len(buf) != expectedSize {
		return fmt.Errorf("invalid %s parameter: got %d bytes, want %d bytes", parameterName, len(buf), expectedSize)
	}
	return nil
}

// Deterministic mode functions

// EncryptIPTo EncryptIP encrypts an IP address using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// The encrypted parameter must be exactly net.IPv6len bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the encrypted IP address as a net.IP.
func EncryptIPTo(key []byte, ip net.IP, encrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, net.IPv6len, "encrypted"); err != nil {
		return nil, err
	}

	ipBytes := []byte(ip)
	if len(ip) != net.IPv6len {
		if err := validateIPTo(ip, encrypted[:net.IPv6len]); err != nil {
			return nil, err
		}
		ipBytes = encrypted[:net.IPv6len]
	}

	block, err := scratch.getAESBlock(1, key)
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
	scratch := ScratchPad{}
	return EncryptIPTo(key, ip, encrypted, &scratch)
}

// DecryptIPTo DecryptIP decrypts an IP address that was encrypted using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// The decrypted parameter must be exactly net.IPv6len bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the decrypted IP address as a net.IP.
func DecryptIPTo(key []byte, encrypted net.IP, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	if err := validateOutputLength(decrypted, net.IPv6len, "decrypted"); err != nil {
		return nil, err
	}

	ipBytes := []byte(encrypted)
	if len(encrypted) != net.IPv6len {
		if err := validateIPTo(encrypted, decrypted[:net.IPv6len]); err != nil {
			return nil, err
		}
		ipBytes = decrypted[:net.IPv6len]
	}

	block, err := scratch.getAESBlock(1, key)
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
	scratch := ScratchPad{}
	return DecryptIPTo(key, encrypted, decrypted, &scratch)
}

// Non-deterministic mode functions

// EncryptIPNonDeterministicTo EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// The encrypted parameter must be exactly NonDeterministicSize bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicTo(ip net.IP, key []byte, tweak []byte, encrypted []byte, scratch *ScratchPad) ([]byte, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, NonDeterministicSize, "encrypted"); err != nil {
		return nil, err
	}

	ipBytes := []byte(ip)
	if len(ip) != net.IPv6len {
		if err := validateIPTo(ip, scratch.scratch1[:net.IPv6len]); err != nil {
			return nil, err
		}
		ipBytes = scratch.scratch1[:net.IPv6len]
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

	roundKeys := scratch.getRoundKeys(1, key)
	if err := kiasuBCEncryptTo(roundKeys, t, ipBytes, encrypted[TweakSize:], scratch.scratch1[:]); err != nil {
		return nil, err
	}
	return encrypted[:NonDeterministicSize], nil
}

// EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error) {
	encrypted := make([]byte, NonDeterministicSize)
	scratch := ScratchPad{}
	return EncryptIPNonDeterministicTo(net.ParseIP(ip), key, tweak, encrypted, &scratch)
}

// DecryptIPNonDeterministicTo decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// The decrypted parameter must be exactly net.IPv6len bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the decrypted IP address as a net.IP.
func DecryptIPNonDeterministicTo(ciphertext []byte, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}

	if len(ciphertext) != NonDeterministicSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), NonDeterministicSize)
	}

	if err := validateOutputLength(decrypted, net.IPv6len, "decrypted"); err != nil {
		return nil, err
	}

	tweak := ciphertext[:TweakSize]
	encryptedIP := ciphertext[TweakSize:]

	roundKeys := scratch.getRoundKeys(1, key)
	if err := kiasuBCDecryptTo(roundKeys, tweak, encryptedIP, decrypted, scratch.scratch1[:]); err != nil {
		return nil, err
	}
	return net.IP(decrypted[:net.IPv6len]), nil
}

// DecryptIPNonDeterministic decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error) {
	decrypted := make([]byte, net.IPv6len)
	scratch := ScratchPad{}
	ip, err := DecryptIPNonDeterministicTo(ciphertext, key, decrypted, &scratch)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}

// Prefix-preserving mode functions

// EncryptIPPfxTo encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly KeySizePFX bytes long (split into two AES-128 keys).
// The encrypted parameter must be exactly net.IPv4len bytes for IPv4 inputs or exactly
// net.IPv6len bytes for IPv6 inputs.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the encrypted IP address in net.IPv4len-byte form for IPv4 callers using a net.IPv4len-byte
// destination buffer, or 16-byte form otherwise.
func EncryptIPPfxTo(ip net.IP, key []byte, encrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizePFX); err != nil {
		return nil, err
	}

	// Split the key into two AES-128 keys
	k1 := key[:aes.BlockSize]
	k2 := key[aes.BlockSize:KeySizePFX]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	var ip16 [net.IPv6len]byte
	ipBytes := []byte(ip)
	if len(ip) != net.IPv6len {
		if err := validateIPTo(ip, ip16[:]); err != nil {
			return nil, err
		}
		ipBytes = ip16[:]
	}

	// Create AES cipher objects
	cipher1, err := scratch.getAESBlock(1, k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := scratch.getAESBlock(2, k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	// Determine if this is IPv4
	isIPv4 := ip.To4() != nil
	encryptedBits := encrypted
	if isIPv4 {
		switch len(encrypted) {
		case net.IPv6len:
			encryptedBits = encrypted[:net.IPv6len]
			copy(encryptedBits[:12], ipv4MappedPrefix[:])
		case net.IPv4len:
			encryptedBits = encrypted[:net.IPv4len]
		default:
			return nil, fmt.Errorf("invalid encrypted parameter: got %d bytes, want %d bytes for IPv4 or %d bytes for IPv6", len(encrypted), net.IPv4len, net.IPv6len)
		}
	} else {
		if err := validateOutputLength(encrypted, net.IPv6len, "encrypted"); err != nil {
			return nil, err
		}
		encryptedBits = encrypted[:net.IPv6len]
	}

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := scratch.scratch1[:]
	if isIPv4 {
		copy(paddedPrefix, pfxIPv4PaddedPrefix[:])
	} else {
		copy(paddedPrefix, pfxIPv6PaddedPrefix[:])
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := scratch.scratch2[:]
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := scratch.scratch3[:]
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytesTo(e1, e2, scratch.scratch4[:])
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the original IP
		currentBitPos := 127 - prefixLenBits
		originalBit := getBit(ipBytes, currentBitPos)

		// Set the bit in the encrypted result
		setBit(encryptedBits, currentBitPos, cipherBit^originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from ipBytes
		shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	return net.IP(encryptedBits), nil
}

// EncryptIPPfx encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly KeySizePFX bytes long (split into two AES-128 keys).
// Returns the encrypted IP address maintaining the original format (IPv4 or IPv6).
func EncryptIPPfx(ip net.IP, key []byte) (net.IP, error) {
	if err := validateKey(key, KeySizePFX); err != nil {
		return nil, err
	}
	var encrypted []byte
	switch len(ip) {
	case net.IPv6len:
		encrypted = make([]byte, net.IPv6len)
	case net.IPv4len:
		encrypted = make([]byte, net.IPv4len)
	default:
		return nil, fmt.Errorf("invalid ip parameter length (%d bytes) - must be either %d bytes or %d bytes", len(ip), net.IPv4len, net.IPv6len)
	}
	scratch := ScratchPad{}
	return EncryptIPPfxTo(ip, key, encrypted, &scratch)
}

// DecryptIPPfxTo decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly KeySizePFX bytes long (split into two AES-128 keys).
// The decrypted parameter must be exactly net.IPv4len bytes for IPv4 inputs or exactly
// net.IPv6len bytes for IPv6 inputs.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the decrypted IP address in net.IPv4len-byte form for IPv4 callers using a net.IPv4len-byte
// destination buffer, or 16-byte form otherwise.
func DecryptIPPfxTo(encryptedIP net.IP, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizePFX); err != nil {
		return nil, err
	}

	// Split the key into two AES-128 keys
	k1 := key[:aes.BlockSize]
	k2 := key[aes.BlockSize:KeySizePFX]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	// Keep IPv4 ciphertexts in their IPv4 code path, but normalize them to
	// the 16-byte IPv4-mapped form before the bitwise decryption loop.
	isIPv4 := encryptedIP.To4() != nil
	decryptedBits := decrypted
	if isIPv4 {
		switch len(decrypted) {
		case net.IPv6len:
			decryptedBits = decrypted[:net.IPv6len]
			copy(decryptedBits[:12], ipv4MappedPrefix[:])
		case net.IPv4len:
			decryptedBits = decrypted[:net.IPv4len]
		default:
			return nil, fmt.Errorf("invalid decrypted parameter: got %d bytes, want %d bytes for IPv4 or %d bytes for IPv6", len(decrypted), net.IPv4len, net.IPv6len)
		}
	} else {
		if err := validateOutputLength(decrypted, net.IPv6len, "decrypted"); err != nil {
			return nil, err
		}
		decryptedBits = decrypted[:net.IPv6len]
	}
	var encryptedIP16 [net.IPv6len]byte
	encryptedBytes := []byte(encryptedIP)
	if isIPv4 && len(encryptedIP) == net.IPv4len {
		encryptedBytes = encryptedIP
	} else if len(encryptedIP) != net.IPv6len {
		if err := validateIPTo(encryptedIP, encryptedIP16[:]); err != nil {
			return nil, err
		}
		encryptedBytes = encryptedIP16[:]
	}

	// Create AES cipher objects
	cipher1, err := scratch.getAESBlock(1, k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := scratch.getAESBlock(2, k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := scratch.scratch1[:]
	if isIPv4 {
		copy(paddedPrefix, pfxIPv4PaddedPrefix[:])
	} else {
		copy(paddedPrefix, pfxIPv6PaddedPrefix[:])
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := scratch.scratch2[:]
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := scratch.scratch3[:]
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytesTo(e1, e2, scratch.scratch4[:])
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the encrypted IP
		currentBitPos := 127 - prefixLenBits
		encryptedBit := getBit(encryptedBytes, currentBitPos)
		originalBit := cipherBit ^ encryptedBit

		// Set the bit in the decrypted result
		setBit(decryptedBits, currentBitPos, originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from decrypted
		shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	return net.IP(decryptedBits), nil
}

// DecryptIPPfx decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly KeySizePFX bytes long (split into two AES-128 keys).
// Returns the decrypted IP address.
func DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error) {
	var decrypted []byte
	switch len(encryptedIP) {
	case net.IPv6len:
		decrypted = make([]byte, net.IPv6len)
	case net.IPv4len:
		decrypted = make([]byte, net.IPv4len)
	default:
		return nil, fmt.Errorf("invalid encryptedIP parameter length (%d bytes) - must be either %d bytes or %d bytes", len(encryptedIP), net.IPv4len, net.IPv6len)
	}
	scratch := ScratchPad{}
	return DecryptIPPfxTo(encryptedIP, key, decrypted, &scratch)
}

// Helper functions for bit manipulation

// getBit extracts a bit at position from the supplied byte slice.
// position: 0 = LSB of the final byte, len(data)*8-1 = MSB of the first byte.
func getBit(data []byte, position int) byte {
	byteIndex := len(data) - 1 - (position / 8)
	bitIndex := position % 8
	return (data[byteIndex] >> bitIndex) & 1
}

// setBit sets a bit at position in the supplied byte slice.
// position: 0 = LSB of the final byte, len(data)*8-1 = MSB of the first byte.
func setBit(data []byte, position int, value byte) {
	byteIndex := len(data) - 1 - (position / 8)
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
// The encrypted parameter must be exactly NonDeterministicXSize bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicXTo(ip net.IP, key []byte, tweak []byte, encrypted []byte, scratch *ScratchPad) ([]byte, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	if err := validateOutputLength(encrypted, NonDeterministicXSize, "encrypted"); err != nil {
		return nil, err
	}
	ipBytes := []byte(ip)
	if len(ip) != net.IPv6len {
		if err := validateIPTo(ip, scratch.scratch4[:]); err != nil {
			return nil, err
		}
		ipBytes = scratch.scratch4[:]
	}

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := scratch.getAESBlock(1, key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := scratch.getAESBlock(2, key2)
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

	encryptedTweak := scratch.scratch1[:]
	block2.Encrypt(encryptedTweak, t)

	xoredIP := xorBytesTo(ipBytes, encryptedTweak, scratch.scratch2[:])
	if xoredIP == nil {
		return nil, errors.New("XOR operation failed")
	}

	block1.Encrypt(encrypted[TweakSizeX:], xoredIP)

	finalEncrypted := xorBytesTo(encrypted[TweakSizeX:], encryptedTweak, scratch.scratch3[:])
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
	scratch := ScratchPad{}
	return EncryptIPNonDeterministicXTo(net.ParseIP(ip), key, tweak, encrypted, &scratch)
}

// DecryptIPNonDeterministicXTo decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// The decrypted parameter must be exactly net.IPv6len bytes long.
// The scratch parameter provides reusable state to avoid allocations across calls.
// Returns the decrypted IP address as a net.IP.
func DecryptIPNonDeterministicXTo(ciphertext []byte, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error) {
	if scratch == nil {
		return nil, errors.New("scratch parameter must not be nil")
	}

	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	if len(ciphertext) != NonDeterministicXSize {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), NonDeterministicXSize)
	}

	if err := validateOutputLength(decrypted, net.IPv6len, "decrypted"); err != nil {
		return nil, err
	}

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := scratch.getAESBlock(1, key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := scratch.getAESBlock(2, key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	tweak := ciphertext[:TweakSizeX]
	encryptedIP := ciphertext[TweakSizeX:]

	encryptedTweak := scratch.scratch1[:]
	block2.Encrypt(encryptedTweak, tweak)

	xoredIP := xorBytesTo(encryptedIP, encryptedTweak, scratch.scratch2[:])
	if xoredIP == nil {
		return nil, errors.New("XOR operation failed")
	}

	block1.Decrypt(decrypted, xoredIP)

	finalDecrypted := xorBytesTo(decrypted, encryptedTweak, scratch.scratch3[:])
	if finalDecrypted == nil {
		return nil, errors.New("XOR operation failed")
	}

	copy(decrypted, finalDecrypted)
	return net.IP(decrypted[:net.IPv6len]), nil
}

// DecryptIPNonDeterministicX decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error) {
	decrypted := make([]byte, net.IPv6len)
	scratch := ScratchPad{}
	ip, err := DecryptIPNonDeterministicXTo(ciphertext, key, decrypted, &scratch)
	if err != nil {
		return "", err
	}

	return ip.String(), nil
}
