package ipcrypt

import "solod.dev/so/net/netip"

// NonDeterministicCipher is an expanded KIASU-BC key for ipcrypt-nd.
// Once initialized it is read-only, so it can be shared between threads.
type NonDeterministicCipher struct {
	rk    roundKeys
	ready bool
}

// Init prepares the cipher from a 16-byte key.
// A cipher whose Init failed stays unusable, so an ignored error cannot turn
// into encryption under an all-zero key.
func (c *NonDeterministicCipher) Init(key []byte) error {
	c.ready = false
	if len(key) != KeySizeND {
		return ErrInvalidKeySize
	}
	expandKey(&c.rk, key)
	c.ready = true
	return nil
}

// EncryptIP encrypts an IP address into dst, which needs NDSize bytes.
// An empty tweak is drawn from the system random source, otherwise it must be
// TweakSize bytes.
// The result is dst[:NDSize], holding the tweak followed by the ciphertext.
func (c *NonDeterministicCipher) EncryptIP(dst []byte, ip netip.Addr, tweak []byte) ([]byte, error) {
	if !c.ready {
		return nil, ErrUninitialized
	}
	if len(dst) < NDSize {
		return nil, ErrShortBuffer
	}
	var in block
	if err := addrTo16(&in, ip); err != nil {
		return nil, err
	}
	if err := resolveTweak(dst[:TweakSize], tweak); err != nil {
		return nil, err
	}
	var out block
	kiasuEncrypt(&out, &c.rk, dst[:TweakSize], &in)
	copy(dst[TweakSize:NDSize], out[:])
	return dst[:NDSize], nil
}

// DecryptIP recovers the address from an NDSize-byte ciphertext.
// An address that started out as IPv4 comes back in its IPv4-mapped IPv6 form,
// so call Unmap on the result to get it back as IPv4.
func (c *NonDeterministicCipher) DecryptIP(ciphertext []byte) (netip.Addr, error) {
	if !c.ready {
		return netip.Addr{}, ErrUninitialized
	}
	if len(ciphertext) != NDSize {
		return netip.Addr{}, ErrInvalidCiphertext
	}
	var in, out block
	copy(in[:], ciphertext[TweakSize:NDSize])
	kiasuDecrypt(&out, &c.rk, ciphertext[:TweakSize], &in)
	return netip.AddrFrom16(out), nil
}

// EncryptIPND encrypts an IP address using ipcrypt-nd.
// The 16-byte key is expanded on every call, so prefer
// [NonDeterministicCipher] when encrypting more than one address.
func EncryptIPND(dst []byte, key []byte, ip netip.Addr, tweak []byte) ([]byte, error) {
	var c NonDeterministicCipher
	if err := c.Init(key); err != nil {
		return nil, err
	}
	return c.EncryptIP(dst, ip, tweak)
}

// DecryptIPND decrypts a ciphertext produced by [EncryptIPND].
func DecryptIPND(key []byte, ciphertext []byte) (netip.Addr, error) {
	var c NonDeterministicCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.DecryptIP(ciphertext)
}
