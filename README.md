# Go Implementation of IPCrypt

This is a Go implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Overview

The implementation provides four methods for IP address encryption:

1. **ipcrypt-deterministic**: A deterministic mode where the same input always produces the same output for a given key.
2. **ipcrypt-nd**: A non-deterministic mode that uses an 8-byte tweak for enhanced privacy.
3. **ipcrypt-ndx**: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak for increased security.
4. **ipcrypt-pfx**: A prefix-preserving mode that maintains the original IP format (IPv4 or IPv6).

## Installation

```sh
go get github.com/jedisct1/go-ipcrypt
```

## Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    "net"
    "github.com/jedisct1/go-ipcrypt"
)

func main() {
    // Create a 16-byte key for ipcrypt-deterministic mode
    key := make([]byte, ipcrypt.KeySizeDeterministic)
    rand.Read(key)

    // Encrypt an IP address (ipcrypt-deterministic mode)
    ip := net.ParseIP("192.168.1.1")
    encrypted, err := ipcrypt.EncryptIP(key, ip)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)

    // Decrypt the IP address
    decrypted, err := ipcrypt.DecryptIP(key, encrypted)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)

    // ipcrypt-nd mode with random tweak
    ndKey := make([]byte, ipcrypt.KeySizeND)
    rand.Read(ndKey)

    encryptedND, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), ndKey, nil)
    if err != nil {
        panic(err)
    }

    decryptedND, err := ipcrypt.DecryptIPNonDeterministic(encryptedND, ndKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Non-deterministic decrypted: %s\n", decryptedND)

    // ipcrypt-ndx mode with random tweak
    xtsKey := make([]byte, ipcrypt.KeySizeNDX)
    rand.Read(xtsKey)

    encryptedX, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), xtsKey, nil)
    if err != nil {
        panic(err)
    }

    decryptedX, err := ipcrypt.DecryptIPNonDeterministicX(encryptedX, xtsKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Extended non-deterministic decrypted: %s\n", decryptedX)
}
```

## API Reference

### Constants

- `KeySizeDeterministic`: 16 bytes (ipcrypt-deterministic)
- `KeySizeND`: 16 bytes (ipcrypt-nd)
- `KeySizeNDX`: 32 bytes (ipcrypt-ndx)
- `KeySizePFX`: 32 bytes (ipcrypt-pfx, split into two AES-128 keys)
- `TweakSize`: 8 bytes (ipcrypt-nd tweak)
- `TweakSizeX`: 16 bytes (ipcrypt-ndx tweak)
- `NonDeterministicSize`: 24 bytes (`TweakSize + net.IPv6len`)
- `NonDeterministicXSize`: 32 bytes (`TweakSizeX + net.IPv6len`)

### Types

- `ScratchPad` - reusable scratch buffers and cached internal state for the zero-allocation `To` APIs across repeated calls
- `NewScratchPad() *ScratchPad` - creates and initializes a scratch pad

### Functions

#### Deterministic Mode
- `EncryptIP(key []byte, ip net.IP) (net.IP, error)` - Encrypts an IP address deterministically
- `DecryptIP(key []byte, encrypted net.IP) (net.IP, error)` - Decrypts an IP address deterministically
- `EncryptIPTo(key []byte, ip net.IP, encrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation deterministic encryption into a preallocated buffer of exactly `net.IPv6len` bytes
- `DecryptIPTo(key []byte, encrypted net.IP, decrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation deterministic decryption into a preallocated buffer of exactly `net.IPv6len` bytes

#### Prefix-Preserving Mode (ipcrypt-pfx)
All `ipcrypt-pfx` functions require a key of exactly `KeySizePFX` bytes, split into two distinct AES-128 keys.

- `EncryptIPPfx(ip net.IP, key []byte) (net.IP, error)` - Encrypts an IP address with prefix preservation
- `DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error)` - Decrypts an IP address with prefix preservation
- `EncryptIPPfxTo(ip net.IP, key []byte, encrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation prefix-preserving encryption into a preallocated buffer of exactly `net.IPv4len` bytes for IPv4 or exactly `net.IPv6len` bytes for IPv6
- `DecryptIPPfxTo(encryptedIP net.IP, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation prefix-preserving decryption into a preallocated buffer of exactly `net.IPv4len` bytes for IPv4 or exactly `net.IPv6len` bytes for IPv6

#### Non-Deterministic Mode (ipcrypt-nd)
- `EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error)` - Encrypts with 8-byte tweak
- `DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error)` - Decrypts ipcrypt-nd ciphertext
- `EncryptIPNonDeterministicTo(ip net.IP, key []byte, tweak []byte, encrypted []byte, scratch *ScratchPad) ([]byte, error)` - Zero-allocation encryption into a preallocated buffer of exactly `NonDeterministicSize` bytes
- `DecryptIPNonDeterministicTo(ciphertext []byte, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation decryption into a preallocated buffer of exactly `net.IPv6len` bytes

#### Extended Non-Deterministic Mode (ipcrypt-ndx)
- `EncryptIPNonDeterministicX(ip string, key []byte, tweak []byte) ([]byte, error)` - Encrypts with 16-byte tweak
- `DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error)` - Decrypts ipcrypt-ndx ciphertext
- `EncryptIPNonDeterministicXTo(ip net.IP, key []byte, tweak []byte, encrypted []byte, scratch *ScratchPad) ([]byte, error)` - Zero-allocation encryption into a preallocated buffer of exactly `NonDeterministicXSize` bytes
- `DecryptIPNonDeterministicXTo(ciphertext []byte, key []byte, decrypted []byte, scratch *ScratchPad) (net.IP, error)` - Zero-allocation decryption into a preallocated buffer of exactly `net.IPv6len` bytes

## Zero-Allocation Usage

The `To` functions write into caller-provided buffers and take a reusable `ScratchPad`. Reusing both across calls gives you zero-allocation behaviour.

```go
scratch := ipcrypt.NewScratchPad()
buf := make([]byte, net.IPv6len) // Use net.IPv4len for IPv4-only callers.

for ip := range ips {
    encrypted, err := ipcrypt.EncryptIPPfxTo(ip, key, buf, scratch)
    if err != nil {
        panic(err)
    }
	// use buf in some way
}
```

Note that the scratch pad must be initialized before use. It is safe to reuse the same scratch pad across different keys, 
but cached cipher state will be rebuilt when the key changes, so you get the best performance when reusing it with the 
same key. A `ScratchPad` must not be shared concurrently across goroutines without external synchronization.

## Performance

Depending on the mode, using the `To` functions can be almost an order of magnitude faster (deterministic and ndx modes) 
if you are performing multiple conversions using the same scratch pad. The `To` functions save around 100+ns per conversion
on a M4 Mac, so the difference is less noticeable for the `nd` and `pfx` modes, which are slower (particularly 
encrypting/decrypting IPV6 addresses in `pfx` mode and descrypting addresses in `nd` mode).

Running `go test -bench BenchmarkAllocations -benchmem` will give you benchmark results for each of the modes and API
calls, for example:
```
goos: darwin
goarch: arm64
pkg: github.com/jedisct1/go-ipcrypt
cpu: Apple M4
BenchmarkAllocations/DeterministicEncrypt/IPv4-10    	 9683328	       104.4 ns/op	     528 B/op	       2 allocs/op
BenchmarkAllocations/DeterministicEncrypt/IPv6-10    	11758062	       101.9 ns/op	     528 B/op	       2 allocs/op
BenchmarkAllocations/DeterministicEncryptTo/IPv4-10  	96331054	        12.76 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/DeterministicEncryptTo/IPv6-10  	96211665	        12.74 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/DeterministicDecrypt/IPv4-10    	11532612	       102.8 ns/op	     528 B/op	       2 allocs/op
BenchmarkAllocations/DeterministicDecrypt/IPv6-10    	11747846	       103.4 ns/op	     528 B/op	       2 allocs/op
BenchmarkAllocations/DeterministicDecryptTo/IPv4-10  	96473685	        12.78 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/DeterministicDecryptTo/IPv6-10  	94559234	        12.98 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDEncrypt/IPv4-10               	 4494896	       264.9 ns/op	      24 B/op	       1 allocs/op
BenchmarkAllocations/NDEncrypt/IPv6-10               	 4378069	       271.8 ns/op	      24 B/op	       1 allocs/op
BenchmarkAllocations/NDEncryptTo/IPv4-10             	 6718228	       179.7 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDEncryptTo/IPv6-10             	 6710262	       179.5 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDDecrypt/IPv4-10               	  530713	      2268 ns/op	       8 B/op	       1 allocs/op
BenchmarkAllocations/NDDecrypt/IPv6-10               	  533724	      2294 ns/op	      16 B/op	       1 allocs/op
BenchmarkAllocations/NDDecryptTo/IPv4-10             	  562756	      2183 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDDecryptTo/IPv6-10             	  547240	      2178 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDXEncrypt/IPv4-10              	 4906118	       244.0 ns/op	    1568 B/op	       4 allocs/op
BenchmarkAllocations/NDXEncrypt/IPv6-10              	 4745586	       253.5 ns/op	    1568 B/op	       4 allocs/op
BenchmarkAllocations/NDXEncryptTo/IPv4-10            	36069930	        33.57 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDXEncryptTo/IPv6-10            	36468759	        33.34 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDXDecrypt/IPv4-10              	 4810798	       248.5 ns/op	    1560 B/op	       5 allocs/op
BenchmarkAllocations/NDXDecrypt/IPv6-10              	 4426274	       266.8 ns/op	    1568 B/op	       5 allocs/op
BenchmarkAllocations/NDXDecryptTo/IPv4-10            	40063990	        29.97 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/NDXDecryptTo/IPv6-10            	40379679	        30.03 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/PFXEncrypt/IPv4-10              	 1335013	       897.1 ns/op	    1552 B/op	       4 allocs/op
BenchmarkAllocations/PFXEncrypt/IPv6-10              	  386245	      3112 ns/op	    1552 B/op	       4 allocs/op
BenchmarkAllocations/PFXEncryptTo/IPv4-10            	 1614217	       744.1 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/PFXEncryptTo/IPv6-10            	  403288	      3010 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/PFXDecrypt/IPv4-10              	 1626735	       735.7 ns/op	    1552 B/op	       4 allocs/op
BenchmarkAllocations/PFXDecrypt/IPv6-10              	  499734	      2430 ns/op	    1552 B/op	       4 allocs/op
BenchmarkAllocations/PFXDecryptTo/IPv4-10            	 2117570	       569.9 ns/op	       0 B/op	       0 allocs/op
BenchmarkAllocations/PFXDecryptTo/IPv6-10            	  507560	      2363 ns/op	       0 B/op	       0 allocs/op
```
