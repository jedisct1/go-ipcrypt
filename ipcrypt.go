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
)

// Tweak sizes for different encryption modes
const (
	TweakSize  = 8  // Size in bytes of the tweak for ipcrypt-nd mode
	TweakSizeX = 16 // Size in bytes of the tweak for ipcrypt-ndx mode
)

// Error definitions for the package
var (
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrInvalidIP      = errors.New("invalid IP address")
	ErrInvalidTweak   = errors.New("invalid tweak size")
)

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

func validateTweak(tweak []byte, expectedSize int) error {
	if len(tweak) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidTweak, len(tweak), expectedSize)
	}
	return nil
}

// xorBytesTo writes a ^ b into dst. dst, a, b must all be the same length.
// dst may be the same slice as a or b (exact overlap), but must not
// partially overlap either input.
func xorBytesTo(dst, a, b []byte) {
	subtle.XORBytes(dst, a, b)
}

// Deterministic mode functions

func encryptIPWithBlockTo(dst []byte, block cipher.Block, ip net.IP) (net.IP, error) {
	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}
	if len(dst) < 16 {
		dst = make([]byte, 16)
	}
	block.Encrypt(dst[:16], ipBytes)
	return net.IP(dst[:16]), nil
}

func decryptIPWithBlockTo(dst []byte, block cipher.Block, encrypted net.IP) (net.IP, error) {
	ipBytes, err := validateIP(encrypted)
	if err != nil {
		return nil, err
	}
	if len(dst) < 16 {
		dst = make([]byte, 16)
	}
	block.Decrypt(dst[:16], ipBytes)
	return net.IP(dst[:16]), nil
}

// EncryptIPTo encrypts an IP address into dst using ipcrypt-deterministic mode.
// dst must be at least 16 bytes; if dst is nil or too short a new buffer is allocated.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns dst[:16] as net.IP.
func EncryptIPTo(dst, key []byte, ip net.IP) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return encryptIPWithBlockTo(dst, block, ip)
}

// EncryptIP encrypts an IP address using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the encrypted IP address as a net.IP.
func EncryptIP(key []byte, ip net.IP) (net.IP, error) {
	return EncryptIPTo(nil, key, ip)
}

// DecryptIPTo decrypts an encrypted IP address into dst using ipcrypt-deterministic mode.
// dst must be at least 16 bytes; if dst is nil or too short a new buffer is allocated.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns dst[:16] as net.IP.
func DecryptIPTo(dst, key []byte, encrypted net.IP) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return decryptIPWithBlockTo(dst, block, encrypted)
}

// DecryptIP decrypts an IP address that was encrypted using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIP(key []byte, encrypted net.IP) (net.IP, error) {
	return DecryptIPTo(nil, key, encrypted)
}

// Non-deterministic mode functions

func encryptNDWithScheduleTo(dst []byte, rk *kiasuRoundKeys, ip string, tweak []byte) ([]byte, error) {
	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	var t []byte
	if tweak == nil {
		t = make([]byte, TweakSize)
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSize); err != nil {
			return nil, err
		}
		t = tweak
	}

	const resultSize = TweakSize + 16
	if len(dst) < resultSize {
		dst = make([]byte, resultSize)
	}
	copy(dst[:TweakSize], t)
	kiasuBCEncryptWithScheduleTo(dst[TweakSize:TweakSize+16], rk, t, ipBytes)
	return dst[:resultSize], nil
}

func decryptNDWithScheduleTo(dst []byte, rk *kiasuRoundKeys, ciphertext []byte) (net.IP, error) {
	if len(ciphertext) != TweakSize+16 {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), TweakSize+16)
	}

	tweak := ciphertext[:TweakSize]
	encryptedIP := ciphertext[TweakSize:]

	if len(dst) < 16 {
		dst = make([]byte, 16)
	}
	kiasuBCDecryptWithScheduleTo(dst[:16], rk, tweak, encryptedIP)
	return net.IP(dst[:16]), nil
}

// EncryptIPNonDeterministicTo encrypts an IP address into dst using ipcrypt-nd mode.
// dst must be at least TweakSize+16 (24) bytes; if dst is nil or too short a new
// buffer is allocated. The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns dst[:24] containing tweak‖ciphertext.
func EncryptIPNonDeterministicTo(dst []byte, ip string, key []byte, tweak []byte) ([]byte, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}
	var rk kiasuRoundKeys
	expandKeyTo(&rk, key)
	return encryptNDWithScheduleTo(dst, &rk, ip, tweak)
}

// EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error) {
	return EncryptIPNonDeterministicTo(nil, ip, key, tweak)
}

// DecryptIPNonDeterministicTo decrypts an IP address into dst using ipcrypt-nd mode.
// dst must be at least 16 bytes; if dst is nil or too short a new buffer is allocated.
// The key must be exactly KeySizeND bytes long.
// Returns the decrypted IP as net.IP (a sub-slice of dst).
func DecryptIPNonDeterministicTo(dst []byte, ciphertext, key []byte) (net.IP, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}
	var rk kiasuRoundKeys
	expandKeyTo(&rk, key)
	return decryptNDWithScheduleTo(dst, &rk, ciphertext)
}

// DecryptIPNonDeterministic decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error) {
	ip, err := DecryptIPNonDeterministicTo(nil, ciphertext, key)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// Prefix-preserving mode functions

func encryptPfxWithCiphersTo(dst []byte, c1, c2 cipher.Block, ip net.IP) (net.IP, error) {
	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	isIPv4 := ip.To4() != nil

	if len(dst) < 16 {
		dst = make([]byte, 16)
	}

	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		copy(dst[:12], ipBytes[:12])
	}

	var paddedPrefix [16]byte
	if isIPv4 {
		paddedPrefix[3] = 0x01
		paddedPrefix[14] = 0xFF
		paddedPrefix[15] = 0xFF
	} else {
		paddedPrefix[15] = 0x01
	}

	var e1, e2 [16]byte
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		c1.Encrypt(e1[:], paddedPrefix[:])
		c2.Encrypt(e2[:], paddedPrefix[:])

		xorBytesTo(e1[:], e1[:], e2[:])
		cipherBit := e1[15] & 1

		currentBitPos := 127 - prefixLenBits
		originalBit := getBit(ipBytes, currentBitPos)

		setBit(dst, currentBitPos, cipherBit^originalBit)

		shiftLeftOneBit(paddedPrefix[:])
		setBit(paddedPrefix[:], 0, originalBit)
	}

	if isIPv4 {
		return net.IP(dst[12:16]), nil
	}
	return net.IP(dst[:16]), nil
}

func decryptPfxWithCiphersTo(dst []byte, c1, c2 cipher.Block, encryptedIP net.IP) (net.IP, error) {
	isIPv4 := encryptedIP.To4() != nil

	encryptedBytes, err := validateIP(encryptedIP)
	if err != nil {
		return nil, err
	}

	if len(dst) < 16 {
		dst = make([]byte, 16)
	}

	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		copy(dst[:12], encryptedBytes[:12])
	}

	var paddedPrefix [16]byte
	if isIPv4 {
		paddedPrefix[3] = 0x01
		paddedPrefix[14] = 0xFF
		paddedPrefix[15] = 0xFF
	} else {
		paddedPrefix[15] = 0x01
	}

	var e1, e2 [16]byte
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		c1.Encrypt(e1[:], paddedPrefix[:])
		c2.Encrypt(e2[:], paddedPrefix[:])

		xorBytesTo(e1[:], e1[:], e2[:])
		cipherBit := e1[15] & 1

		currentBitPos := 127 - prefixLenBits
		encryptedBit := getBit(encryptedBytes, currentBitPos)
		originalBit := cipherBit ^ encryptedBit

		setBit(dst, currentBitPos, originalBit)

		shiftLeftOneBit(paddedPrefix[:])
		setBit(paddedPrefix[:], 0, originalBit)
	}

	if isIPv4 {
		return net.IP(dst[12:16]), nil
	}
	return net.IP(dst[:16]), nil
}

func validatePfxKey(key []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("%w: got %d bytes, want 32 bytes", ErrInvalidKeySize, len(key))
	}
	k1 := key[:16]
	k2 := key[16:32]
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, nil, errors.New("the two halves of the key must be different")
	}
	return k1, k2, nil
}

// EncryptIPPfxTo encrypts an IP address into dst using ipcrypt-pfx mode.
// dst must be at least 16 bytes even for IPv4 inputs; if dst is nil or too short
// a new buffer is allocated. The key must be exactly 32 bytes long.
// For IPv4 the returned net.IP is dst[12:16]; for IPv6 it is dst[:16].
func EncryptIPPfxTo(dst []byte, ip net.IP, key []byte) (net.IP, error) {
	k1, k2, err := validatePfxKey(key)
	if err != nil {
		return nil, err
	}
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}
	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}
	return encryptPfxWithCiphersTo(dst, cipher1, cipher2, ip)
}

// EncryptIPPfx encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the encrypted IP address maintaining the original format (IPv4 or IPv6).
func EncryptIPPfx(ip net.IP, key []byte) (net.IP, error) {
	return EncryptIPPfxTo(nil, ip, key)
}

// DecryptIPPfxTo decrypts an encrypted IP address into dst using ipcrypt-pfx mode.
// dst must be at least 16 bytes even for IPv4 inputs; if dst is nil or too short
// a new buffer is allocated. The key must be exactly 32 bytes long.
// For IPv4 the returned net.IP is dst[12:16]; for IPv6 it is dst[:16].
func DecryptIPPfxTo(dst []byte, encryptedIP net.IP, key []byte) (net.IP, error) {
	k1, k2, err := validatePfxKey(key)
	if err != nil {
		return nil, err
	}
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}
	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}
	return decryptPfxWithCiphersTo(dst, cipher1, cipher2, encryptedIP)
}

// DecryptIPPfx decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the decrypted IP address.
func DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error) {
	return DecryptIPPfxTo(nil, encryptedIP, key)
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

// shiftLeftOneBit shifts a 16-byte array one bit to the left in-place.
// The most significant bit is lost, and a zero bit is shifted in from the right.
func shiftLeftOneBit(data []byte) {
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		newCarry := (data[i] >> 7) & 1
		data[i] = (data[i] << 1) | carry
		carry = newCarry
	}
}

// Extended non-deterministic mode functions

func encryptNDXWithBlocksTo(dst []byte, block1, block2 cipher.Block, ipBytes, t []byte) []byte {
	const resultSize = TweakSizeX + 16
	if len(dst) < resultSize {
		dst = make([]byte, resultSize)
	}

	var encryptedTweak [16]byte
	block2.Encrypt(encryptedTweak[:], t)

	var xored [16]byte
	xorBytesTo(xored[:], ipBytes, encryptedTweak[:])

	var enc [16]byte
	block1.Encrypt(enc[:], xored[:])

	xorBytesTo(dst[TweakSizeX:TweakSizeX+16], enc[:], encryptedTweak[:])
	copy(dst[:TweakSizeX], t)
	return dst[:resultSize]
}

func decryptNDXWithBlocksTo(dst []byte, block1, block2 cipher.Block, ciphertext []byte) net.IP {
	twk := ciphertext[:TweakSizeX]
	encryptedIP := ciphertext[TweakSizeX:]

	var encryptedTweak [16]byte
	block2.Encrypt(encryptedTweak[:], twk)

	var xored [16]byte
	xorBytesTo(xored[:], encryptedIP, encryptedTweak[:])

	var dec [16]byte
	block1.Decrypt(dec[:], xored[:])

	if len(dst) < 16 {
		dst = make([]byte, 16)
	}
	xorBytesTo(dst[:16], dec[:], encryptedTweak[:])
	return net.IP(dst[:16])
}

// EncryptIPNonDeterministicXTo encrypts an IP address into dst using ipcrypt-ndx mode.
// dst must be at least TweakSizeX+16 (32) bytes; if dst is nil or too short a new
// buffer is allocated. The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns dst[:32] containing tweak‖ciphertext.
func EncryptIPNonDeterministicXTo(dst []byte, ip string, key []byte, tweak []byte) ([]byte, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	block1, err := aes.NewCipher(key[:KeySizeND])
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key[KeySizeND:])
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	var t []byte
	if tweak == nil {
		t = make([]byte, TweakSizeX)
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSizeX); err != nil {
			return nil, err
		}
		t = tweak
	}

	return encryptNDXWithBlocksTo(dst, block1, block2, ipBytes, t), nil
}

// EncryptIPNonDeterministicX encrypts an IP address using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicX(ip string, key []byte, tweak []byte) ([]byte, error) {
	return EncryptIPNonDeterministicXTo(nil, ip, key, tweak)
}

// DecryptIPNonDeterministicXTo decrypts an IP address into dst using ipcrypt-ndx mode.
// dst must be at least 16 bytes; if dst is nil or too short a new buffer is allocated.
// The key must be exactly KeySizeNDX bytes long.
// Returns the decrypted IP as net.IP (a sub-slice of dst).
func DecryptIPNonDeterministicXTo(dst []byte, ciphertext, key []byte) (net.IP, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	if len(ciphertext) != TweakSizeX+16 {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), TweakSizeX+16)
	}

	block1, err := aes.NewCipher(key[:KeySizeND])
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key[KeySizeND:])
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	return decryptNDXWithBlocksTo(dst, block1, block2, ciphertext), nil
}

// DecryptIPNonDeterministicX decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error) {
	ip, err := DecryptIPNonDeterministicXTo(nil, ciphertext, key)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}
