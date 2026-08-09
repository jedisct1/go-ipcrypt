// Package ipcrypt implements the IPCrypt IP address encryption and
// obfuscation methods for Solod (So).
//
// Four modes are provided:
//
//   - ipcrypt-deterministic: the same input always produces the same output
//   - ipcrypt-nd: non-deterministic, using an 8-byte tweak
//   - ipcrypt-ndx: non-deterministic, using a 32-byte key and a 16-byte tweak
//   - ipcrypt-pfx: prefix-preserving, keeping the original address family
//
// Addresses are [netip.Addr] values, so nothing here allocates: every function
// either returns a value or writes into a buffer the caller owns.
// The cipher types hold an expanded key schedule and are meant to be reused.
//
// For the non-deterministic modes, passing an empty tweak makes the package
// draw one from the system random source.
package ipcrypt

import (
	"solod.dev/so/crypto/crand"
	"solod.dev/so/errors"
	"solod.dev/so/net/netip"
)

// Sizes in bytes of the keys, tweaks and blocks used by the four modes.
const (
	BlockSize            = 16
	KeySizeDeterministic = 16
	KeySizeND            = 16
	KeySizeNDX           = 32
	KeySizePfx           = 32
	TweakSize            = 8
	TweakSizeX           = 16

	// NDSize is the length of an ipcrypt-nd ciphertext (tweak and block).
	NDSize = TweakSize + BlockSize
	// NDXSize is the length of an ipcrypt-ndx ciphertext (tweak and block).
	NDXSize = TweakSizeX + BlockSize
)

// Errors reported by this package.
// So has no error wrapping, so these are compared with == and carry no detail.
var (
	ErrInvalidKeySize    = errors.New("ipcrypt: invalid key size")
	ErrInvalidTweakSize  = errors.New("ipcrypt: invalid tweak size")
	ErrInvalidBlockSize  = errors.New("ipcrypt: invalid block size")
	ErrInvalidIP         = errors.New("ipcrypt: invalid IP address")
	ErrInvalidCiphertext = errors.New("ipcrypt: invalid ciphertext length")
	ErrShortBuffer       = errors.New("ipcrypt: destination buffer too short")
	ErrKeyHalvesEqual    = errors.New("ipcrypt: the two halves of the key must differ")
	ErrUninitialized     = errors.New("ipcrypt: cipher has no key, call Init first")
)

// addrTo16 writes the 16-byte form of ip into dst.
// IPv4 addresses come out in their IPv4-mapped IPv6 form, which is what every
// IPCrypt mode operates on.
func addrTo16(dst *block, ip netip.Addr) error {
	if !ip.IsValid() {
		return ErrInvalidIP
	}
	var a16 [16]byte
	a16 = ip.As16(a16)
	copy(dst[:], a16[:])
	return nil
}

// resolveTweak fills dst with the caller's tweak, or with fresh random bytes
// when no tweak was given.
// dst is exactly as long as the mode's tweak.
func resolveTweak(dst []byte, tweak []byte) error {
	if len(tweak) == 0 {
		_, err := crand.Read(dst)
		return err
	}
	if len(tweak) != len(dst) {
		return ErrInvalidTweakSize
	}
	copy(dst, tweak)
	return nil
}

// ctEqual compares a and b in time independent of their contents.
// Both must have the same length.
func ctEqual(a, b []byte) bool {
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// xorBlock writes a ^ b into dst, which may be either of them.
func xorBlock(dst, a, b *block) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}
