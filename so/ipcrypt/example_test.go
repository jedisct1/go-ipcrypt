package ipcrypt_test

import (
	"fmt"

	"solod.dev/so/net/netip"

	"github.com/jedisct1/go-ipcrypt/so/ipcrypt"
)

func ExampleDeterministicCipher() {
	key := []byte("sixteen byte key")

	var c ipcrypt.DeterministicCipher
	if err := c.Init(key); err != nil {
		panic(err)
	}

	encrypted, err := c.EncryptIP(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		panic(err)
	}
	decrypted, err := c.DecryptIP(encrypted)
	if err != nil {
		panic(err)
	}

	var buf [netip.MaxAddrLen]byte
	fmt.Println(decrypted.Unmap().String(buf[:]))
	// Output: 192.0.2.1
}

// Addresses that share a prefix still share one once encrypted, which is what
// ipcrypt-pfx is for.
func ExamplePfxCipher() {
	key := []byte("0123456789abcdeffedcba9876543210")

	var c ipcrypt.PfxCipher
	if err := c.Init(key); err != nil {
		panic(err)
	}

	var buf [netip.MaxAddrLen]byte
	for _, s := range []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"} {
		encrypted, err := c.EncryptIP(netip.MustParseAddr(s))
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s -> %s\n", s, encrypted.String(buf[:]))
	}
	// Output:
	// 192.0.2.1 -> 176.224.19.214
	// 192.0.2.2 -> 176.224.19.212
	// 198.51.100.1 -> 183.210.86.208
}
