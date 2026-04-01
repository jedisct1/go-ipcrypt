package ipcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
)

// DeterministicCipher holds precomputed AES state for repeated
// ipcrypt-deterministic operations with the same key.
// It is safe for concurrent use.
type DeterministicCipher struct {
	block cipher.Block
}

// NewDeterministicCipher creates a DeterministicCipher from a 16-byte key.
func NewDeterministicCipher(key []byte) (*DeterministicCipher, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return &DeterministicCipher{block: block}, nil
}

// EncryptIPTo encrypts ip into dst. dst must be at least 16 bytes;
// if nil or too short a new buffer is allocated. Returns dst[:16] as net.IP.
func (c *DeterministicCipher) EncryptIPTo(dst []byte, ip net.IP) (net.IP, error) {
	return encryptIPWithBlockTo(dst, c.block, ip)
}

// EncryptIP encrypts an IP address. Returns the encrypted IP as net.IP.
func (c *DeterministicCipher) EncryptIP(ip net.IP) (net.IP, error) {
	return encryptIPWithBlockTo(nil, c.block, ip)
}

// DecryptIPTo decrypts encrypted into dst. dst must be at least 16 bytes;
// if nil or too short a new buffer is allocated. Returns dst[:16] as net.IP.
func (c *DeterministicCipher) DecryptIPTo(dst []byte, encrypted net.IP) (net.IP, error) {
	return decryptIPWithBlockTo(dst, c.block, encrypted)
}

// DecryptIP decrypts an encrypted IP address. Returns the decrypted IP as net.IP.
func (c *DeterministicCipher) DecryptIP(encrypted net.IP) (net.IP, error) {
	return decryptIPWithBlockTo(nil, c.block, encrypted)
}

// NonDeterministicCipher holds precomputed KIASU-BC round keys for repeated
// ipcrypt-nd operations with the same key.
// It is safe for concurrent use.
type NonDeterministicCipher struct {
	roundKeys kiasuRoundKeys
}

// NewNonDeterministicCipher creates a NonDeterministicCipher from a 16-byte key.
func NewNonDeterministicCipher(key []byte) (*NonDeterministicCipher, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}
	c := &NonDeterministicCipher{}
	expandKeyTo(&c.roundKeys, key)
	return c, nil
}

// EncryptIPTo encrypts ip into dst (≥ 24 bytes). If tweak is nil a random
// tweak is generated. Returns dst[:24] containing tweak‖ciphertext.
func (c *NonDeterministicCipher) EncryptIPTo(dst []byte, ip string, tweak []byte) ([]byte, error) {
	return encryptNDWithScheduleTo(dst, &c.roundKeys, ip, tweak)
}

// EncryptIP encrypts an IP address with an 8-byte tweak. If tweak is nil a
// random tweak is generated. Returns tweak‖ciphertext.
func (c *NonDeterministicCipher) EncryptIP(ip string, tweak []byte) ([]byte, error) {
	return encryptNDWithScheduleTo(nil, &c.roundKeys, ip, tweak)
}

// DecryptIPTo decrypts ciphertext into dst (≥ 16 bytes).
// Returns the decrypted IP as net.IP.
func (c *NonDeterministicCipher) DecryptIPTo(dst []byte, ciphertext []byte) (net.IP, error) {
	return decryptNDWithScheduleTo(dst, &c.roundKeys, ciphertext)
}

// DecryptIP decrypts ciphertext. Returns the decrypted IP as a string.
func (c *NonDeterministicCipher) DecryptIP(ciphertext []byte) (string, error) {
	ip, err := decryptNDWithScheduleTo(nil, &c.roundKeys, ciphertext)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// NonDeterministicXCipher holds precomputed AES state for repeated
// ipcrypt-ndx operations with the same key.
// It is safe for concurrent use.
type NonDeterministicXCipher struct {
	block1 cipher.Block
	block2 cipher.Block
}

// NewNonDeterministicXCipher creates a NonDeterministicXCipher from a 32-byte key.
func NewNonDeterministicXCipher(key []byte) (*NonDeterministicXCipher, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
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
	return &NonDeterministicXCipher{block1: block1, block2: block2}, nil
}

// EncryptIPTo encrypts ip into dst (≥ 32 bytes). If tweak is nil a random
// tweak is generated. Returns dst[:32] containing tweak‖ciphertext.
func (c *NonDeterministicXCipher) EncryptIPTo(dst []byte, ip string, tweak []byte) ([]byte, error) {
	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
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

	return encryptNDXWithBlocksTo(dst, c.block1, c.block2, ipBytes, t), nil
}

// EncryptIP encrypts an IP address with a 16-byte tweak. If tweak is nil a
// random tweak is generated. Returns tweak‖ciphertext.
func (c *NonDeterministicXCipher) EncryptIP(ip string, tweak []byte) ([]byte, error) {
	return c.EncryptIPTo(nil, ip, tweak)
}

// DecryptIPTo decrypts ciphertext into dst (≥ 16 bytes).
// Returns the decrypted IP as net.IP.
func (c *NonDeterministicXCipher) DecryptIPTo(dst []byte, ciphertext []byte) (net.IP, error) {
	if len(ciphertext) != TweakSizeX+16 {
		return nil, fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), TweakSizeX+16)
	}
	return decryptNDXWithBlocksTo(dst, c.block1, c.block2, ciphertext), nil
}

// DecryptIP decrypts ciphertext. Returns the decrypted IP as a string.
func (c *NonDeterministicXCipher) DecryptIP(ciphertext []byte) (string, error) {
	ip, err := c.DecryptIPTo(nil, ciphertext)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// PfxCipher holds precomputed AES state for repeated ipcrypt-pfx operations
// with the same key.
// It is safe for concurrent use.
type PfxCipher struct {
	block1 cipher.Block
	block2 cipher.Block
}

// NewPfxCipher creates a PfxCipher from a 32-byte key.
// The two 16-byte halves of the key must differ.
func NewPfxCipher(key []byte) (*PfxCipher, error) {
	k1, k2, err := validatePfxKey(key)
	if err != nil {
		return nil, err
	}
	block1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}
	block2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}
	return &PfxCipher{block1: block1, block2: block2}, nil
}

// EncryptIPTo encrypts ip into dst (≥ 16 bytes).
// For IPv4 the returned net.IP is dst[12:16]; for IPv6 it is dst[:16].
func (c *PfxCipher) EncryptIPTo(dst []byte, ip net.IP) (net.IP, error) {
	return encryptPfxWithCiphersTo(dst, c.block1, c.block2, ip)
}

// EncryptIP encrypts an IP address with prefix preservation.
func (c *PfxCipher) EncryptIP(ip net.IP) (net.IP, error) {
	return encryptPfxWithCiphersTo(nil, c.block1, c.block2, ip)
}

// DecryptIPTo decrypts encryptedIP into dst (≥ 16 bytes).
// For IPv4 the returned net.IP is dst[12:16]; for IPv6 it is dst[:16].
func (c *PfxCipher) DecryptIPTo(dst []byte, encryptedIP net.IP) (net.IP, error) {
	return decryptPfxWithCiphersTo(dst, c.block1, c.block2, encryptedIP)
}

// DecryptIP decrypts an encrypted IP address with prefix preservation.
func (c *PfxCipher) DecryptIP(encryptedIP net.IP) (net.IP, error) {
	return decryptPfxWithCiphersTo(nil, c.block1, c.block2, encryptedIP)
}
