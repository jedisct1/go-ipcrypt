package ipcrypt

import "solod.dev/so/net/netip"

// PfxCipher is a pair of expanded AES-128 keys for ipcrypt-pfx.
// Once initialized it is read-only, so it can be shared between threads.
type PfxCipher struct {
	rk1   roundKeys
	rk2   roundKeys
	ready bool
}

// Init prepares the cipher from a 32-byte key, whose halves become two
// independent AES-128 keys and must differ.
// A cipher whose Init failed stays unusable, so an ignored error cannot turn
// into encryption under an all-zero key.
func (c *PfxCipher) Init(key []byte) error {
	c.ready = false
	if len(key) != KeySizePfx {
		return ErrInvalidKeySize
	}
	if ctEqual(key[:16], key[16:32]) {
		return ErrKeyHalvesEqual
	}
	expandKey(&c.rk1, key[:16])
	expandKey(&c.rk2, key[16:32])
	c.ready = true
	return nil
}

// EncryptIP encrypts an IP address so that two addresses sharing an n-bit
// prefix still share an n-bit prefix once encrypted.
// The result keeps the address family of the input.
func (c *PfxCipher) EncryptIP(ip netip.Addr) (netip.Addr, error) {
	return c.transform(ip, false)
}

// DecryptIP recovers the address encrypted by [PfxCipher.EncryptIP].
func (c *PfxCipher) DecryptIP(encrypted netip.Addr) (netip.Addr, error) {
	return c.transform(encrypted, true)
}

// transform runs the prefix-preserving bit walk.
// Encryption and decryption differ only in which bit feeds the growing prefix:
// the input bit when encrypting, the recovered one when decrypting.
func (c *PfxCipher) transform(ip netip.Addr, decrypt bool) (netip.Addr, error) {
	if !c.ready {
		return netip.Addr{}, ErrUninitialized
	}
	var in [16]byte
	if err := addrTo16(in[:], ip); err != nil {
		return netip.Addr{}, err
	}
	isIPv4 := ip.Is4() || ip.Is4In6()

	var out [16]byte
	var paddedPrefix [16]byte
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		paddedPrefix[3] = 0x01
		paddedPrefix[14] = 0xFF
		paddedPrefix[15] = 0xFF
	} else {
		paddedPrefix[15] = 0x01
	}

	var e1, e2 [16]byte
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		encryptBlock(e1[:], &c.rk1, paddedPrefix[:])
		encryptBlock(e2[:], &c.rk2, paddedPrefix[:])
		// Only the last bit of the XOR of the two ciphertexts is used.
		cipherBit := (e1[15] ^ e2[15]) & 1

		currentBitPos := 127 - prefixLenBits
		inputBit := getBit(in[:], currentBitPos)
		outputBit := cipherBit ^ inputBit
		setBit(out[:], currentBitPos, outputBit)

		plainBit := inputBit
		if decrypt {
			plainBit = outputBit
		}
		shiftLeftOneBit(paddedPrefix[:])
		setBit(paddedPrefix[:], 0, plainBit)
	}

	if isIPv4 {
		return netip.AddrFromSlice(out[12:16]), nil
	}
	return netip.AddrFrom16(out), nil
}

// EncryptIPPfx encrypts an IP address using ipcrypt-pfx.
// The 32-byte key is expanded on every call, so prefer [PfxCipher] when
// encrypting more than one address.
func EncryptIPPfx(key []byte, ip netip.Addr) (netip.Addr, error) {
	var c PfxCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.EncryptIP(ip)
}

// DecryptIPPfx decrypts an address encrypted with [EncryptIPPfx].
func DecryptIPPfx(key []byte, encrypted netip.Addr) (netip.Addr, error) {
	var c PfxCipher
	if err := c.Init(key); err != nil {
		return netip.Addr{}, err
	}
	return c.DecryptIP(encrypted)
}

// getBit reads the bit at position in a 16-byte big-endian value.
// Position 0 is the least significant bit of the last byte, 127 the most
// significant bit of the first.
func getBit(data []byte, position int) byte {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	return (data[byteIndex] >> bitIndex) & 1
}

// setBit writes the bit at position in a 16-byte big-endian value.
func setBit(data []byte, position int, value byte) {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	if value != 0 {
		data[byteIndex] |= 1 << bitIndex
	} else {
		data[byteIndex] &= ^(byte(1) << bitIndex)
	}
}

// shiftLeftOneBit shifts a 16-byte value one bit to the left, in place.
// The most significant bit is dropped and a zero comes in from the right.
func shiftLeftOneBit(data []byte) {
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		newCarry := (data[i] >> 7) & 1
		data[i] = (data[i] << 1) | carry
		carry = newCarry
	}
}
