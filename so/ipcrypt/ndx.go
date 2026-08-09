package ipcrypt

import "solod.dev/so/net/netip"

// NonDeterministicXCipher is a pair of expanded AES-128 keys for ipcrypt-ndx.
// Once initialized it is read-only, so it can be shared between threads.
type NonDeterministicXCipher struct {
	rk1   roundKeys
	rk2   roundKeys
	ready bool
}

// Init prepares the cipher from a 32-byte key, whose halves become two
// independent AES-128 keys.
// A cipher whose Init failed stays unusable, so an ignored error cannot turn
// into encryption under an all-zero key.
func (c *NonDeterministicXCipher) Init(key []byte) error {
	c.ready = false
	if len(key) != KeySizeNDX {
		return ErrInvalidKeySize
	}
	expandKey(&c.rk1, key[:16])
	expandKey(&c.rk2, key[16:32])
	c.ready = true
	return nil
}

// EncryptIP encrypts an IP address into dst, which needs NDXSize bytes.
// An empty tweak is drawn from the system random source, otherwise it must be
// TweakSizeX bytes.
// The result is dst[:NDXSize], holding the tweak followed by the ciphertext.
func (c *NonDeterministicXCipher) EncryptIP(dst []byte, ip netip.Addr, tweak []byte) ([]byte, error) {
	if !c.ready {
		return nil, ErrUninitialized
	}
	if len(dst) < NDXSize {
		return nil, ErrShortBuffer
	}
	var in [16]byte
	if err := addrTo16(in[:], ip); err != nil {
		return nil, err
	}
	if err := resolveTweak(dst[:TweakSizeX], tweak); err != nil {
		return nil, err
	}

	var encryptedTweak [16]byte
	encryptBlock(encryptedTweak[:], &c.rk2, dst[:TweakSizeX])

	xorInto(in[:], in[:], encryptedTweak[:])
	encryptBlock(in[:], &c.rk1, in[:])
	xorInto(dst[TweakSizeX:NDXSize], in[:], encryptedTweak[:])
	return dst[:NDXSize], nil
}

// DecryptIP recovers the address from an NDXSize-byte ciphertext.
// An address that started out as IPv4 comes back in its IPv4-mapped IPv6 form,
// so call Unmap on the result to get it back as IPv4.
func (c *NonDeterministicXCipher) DecryptIP(ciphertext []byte) (netip.Addr, error) {
	if !c.ready {
		return netip.Addr{}, ErrUninitialized
	}
	if len(ciphertext) != NDXSize {
		return netip.Addr{}, ErrInvalidCiphertext
	}

	var encryptedTweak [16]byte
	encryptBlock(encryptedTweak[:], &c.rk2, ciphertext[:TweakSizeX])

	var out [16]byte
	xorInto(out[:], ciphertext[TweakSizeX:NDXSize], encryptedTweak[:])
	decryptBlock(out[:], &c.rk1, out[:])
	xorInto(out[:], out[:], encryptedTweak[:])
	return netip.AddrFrom16(out), nil
}

// EncryptIPNDX encrypts an IP address using ipcrypt-ndx.
// The 32-byte key is expanded on every call, so prefer
// [NonDeterministicXCipher] when encrypting more than one address.
func EncryptIPNDX(dst []byte, key []byte, ip netip.Addr, tweak []byte) ([]byte, error) {
	var c NonDeterministicXCipher
	if err := c.Init(key); err != nil {
		return nil, err
	}
	return c.EncryptIP(dst, ip, tweak)
}

// DecryptIPNDX decrypts a ciphertext produced by [EncryptIPNDX].
func DecryptIPNDX(key []byte, ciphertext []byte) (netip.Addr, error) {
	var c NonDeterministicXCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.DecryptIP(ciphertext)
}
