// Command example encrypts a couple of addresses with each IPCrypt mode.
//
// Run it with:
//
//	so run ./example
package main

import (
	"solod.dev/so/encoding/hex"
	"solod.dev/so/net/netip"

	"github.com/jedisct1/go-ipcrypt/so/ipcrypt"
)

const (
	key16 = "2b7e151628aed2a6abf7158809cf4f3c"
	key32 = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
)

func decodeKey(dst []byte, s string) []byte {
	n, err := hex.Decode(dst, []byte(s))
	if err != nil {
		panic("invalid key")
	}
	return dst[:n]
}

func main() {
	var short, long [32]byte
	k16 := decodeKey(short[:], key16)
	k32 := decodeKey(long[:], key32)

	ip := netip.MustParseAddr("192.0.2.1")
	var out [netip.MaxAddrLen]byte

	// ipcrypt-deterministic: the same address always maps to the same output,
	// which is what makes it joinable across data sets.
	var det ipcrypt.DeterministicCipher
	if err := det.Init(k16); err != nil {
		panic(err)
	}
	encrypted, err := det.EncryptIP(ip)
	if err != nil {
		panic(err)
	}
	println("deterministic:", encrypted.String(out[:]))

	decrypted, err := det.DecryptIP(encrypted)
	if err != nil {
		panic(err)
	}
	println("recovered:    ", decrypted.Unmap().String(out[:]))

	// ipcrypt-nd: an empty tweak means "pick a random one", so the same address
	// encrypts differently every time.
	var nd ipcrypt.NonDeterministicCipher
	if err := nd.Init(k16); err != nil {
		panic(err)
	}
	var buf [ipcrypt.NDSize]byte
	ciphertext, err := nd.EncryptIP(buf[:], ip, nil)
	if err != nil {
		panic(err)
	}
	var hexOut [2 * ipcrypt.NDSize]byte
	hex.Encode(hexOut[:], ciphertext)
	println("nd:           ", string(hexOut[:]))

	decrypted, err = nd.DecryptIP(ciphertext)
	if err != nil {
		panic(err)
	}
	println("recovered:    ", decrypted.Unmap().String(out[:]))

	// ipcrypt-pfx: addresses in the same network stay in the same network once
	// encrypted, and IPv4 stays IPv4.
	var pfx ipcrypt.PfxCipher
	if err := pfx.Init(k32); err != nil {
		panic(err)
	}
	neighbors := []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"}
	for i := 0; i < len(neighbors); i++ {
		addr := netip.MustParseAddr(neighbors[i])
		encrypted, err = pfx.EncryptIP(addr)
		if err != nil {
			panic(err)
		}
		println("pfx:          ", neighbors[i], "->", encrypted.String(out[:]))
	}
}
