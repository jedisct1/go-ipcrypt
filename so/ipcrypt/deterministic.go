package ipcrypt

import "solod.dev/so/net/netip"

// DeterministicCipher is an expanded key for ipcrypt-deterministic.
// Once initialized it is read-only, so it can be shared between threads.
type DeterministicCipher struct {
	rk    roundKeys
	ready bool
}

// Init prepares the cipher from a 16-byte key.
// A cipher whose Init failed stays unusable, so an ignored error cannot turn
// into encryption under an all-zero key.
func (c *DeterministicCipher) Init(key []byte) error {
	c.ready = false
	if len(key) != KeySizeDeterministic {
		return ErrInvalidKeySize
	}
	expandKey(&c.rk, key)
	c.ready = true
	return nil
}

// EncryptIP encrypts an IP address.
// The result is always IPv6, since the ciphertext spans all 128 bits.
func (c *DeterministicCipher) EncryptIP(ip netip.Addr) (netip.Addr, error) {
	if !c.ready {
		return netip.Addr{}, ErrUninitialized
	}
	var in block
	if err := addrTo16(&in, ip); err != nil {
		return netip.Addr{}, err
	}
	var out block
	encryptBlock(&out, &c.rk, &in)
	return netip.AddrFrom16(out), nil
}

// DecryptIP recovers the address encrypted by [DeterministicCipher.EncryptIP].
// An address that started out as IPv4 comes back in its IPv4-mapped IPv6 form,
// so call Unmap on the result to get it back as IPv4.
func (c *DeterministicCipher) DecryptIP(encrypted netip.Addr) (netip.Addr, error) {
	if !c.ready {
		return netip.Addr{}, ErrUninitialized
	}
	var in block
	if err := addrTo16(&in, encrypted); err != nil {
		return netip.Addr{}, err
	}
	var out block
	decryptBlock(&out, &c.rk, &in)
	return netip.AddrFrom16(out), nil
}

// EncryptIP encrypts an IP address using ipcrypt-deterministic.
// The 16-byte key is expanded on every call, so prefer [DeterministicCipher]
// when encrypting more than one address.
func EncryptIP(key []byte, ip netip.Addr) (netip.Addr, error) {
	var c DeterministicCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.EncryptIP(ip)
}

// DecryptIP decrypts an address encrypted with [EncryptIP].
func DecryptIP(key []byte, encrypted netip.Addr) (netip.Addr, error) {
	var c DeterministicCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.DecryptIP(encrypted)
}
