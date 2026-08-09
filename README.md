# Go Implementation of IPCrypt

This is a Go implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Overview

The implementation provides four methods for IP address encryption:

1. **ipcrypt-deterministic**: A deterministic mode where the same input always produces the same output for a given key.
2. **ipcrypt-nd**: A non-deterministic mode that uses an 8-byte tweak for enhanced privacy.
3. **ipcrypt-ndx**: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak for increased security.
4. **ipcrypt-pfx**: A prefix-preserving mode that maintains the original IP format (IPv4 or IPv6).

Every mode provides a `*To` variant that writes into a caller-supplied destination
buffer, enabling callers to control allocations. The original functions are thin
wrappers around these variants.

A port for [Solod](https://solod.dev/), the Go subset that transpiles to C, is
available in [so/](so/). It is a separate module, so it adds nothing to this
package's dependencies.

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

    // Zero-alloc deterministic mode using a pre-allocated buffer
    dst := make([]byte, 16)
    encrypted, err = ipcrypt.EncryptIPTo(dst, key, ip)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted (into dst): %s\n", encrypted)

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
    ndxKey := make([]byte, ipcrypt.KeySizeNDX)
    rand.Read(ndxKey)

    encryptedX, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), ndxKey, nil)
    if err != nil {
        panic(err)
    }

    decryptedX, err := ipcrypt.DecryptIPNonDeterministicX(encryptedX, ndxKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Extended non-deterministic decrypted: %s\n", decryptedX)

    // ipcrypt-pfx mode (prefix-preserving)
    pfxKey := make([]byte, 32)
    rand.Read(pfxKey)

    encryptedPfx, err := ipcrypt.EncryptIPPfx(ip, pfxKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Prefix-preserving encrypted: %s\n", encryptedPfx)

    decryptedPfx, err := ipcrypt.DecryptIPPfx(encryptedPfx, pfxKey)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Prefix-preserving decrypted: %s\n", decryptedPfx)
}
```

### Hot-path: cached ciphers

For repeated operations with the same key, create a cached cipher once and
reuse it. This is the preferred API for hot paths, and the `*To` methods let
you control allocations entirely:

```go
// Hot-path: reuse a cached cipher for repeated operations
c, err := ipcrypt.NewDeterministicCipher(key)
if err != nil {
    panic(err)
}

buf := make([]byte, 16)
for _, ip := range ips {
    encrypted, err := c.EncryptIPTo(buf, ip)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)
}
```

The top-level functions (`EncryptIP`, `EncryptIPNonDeterministic`, etc.) remain
perfectly fine for occasional one-shot calls.

## API Reference

### Constants

- `KeySizeDeterministic`: 16 bytes (ipcrypt-deterministic)
- `KeySizeND`: 16 bytes (ipcrypt-nd)
- `KeySizeNDX`: 32 bytes (ipcrypt-ndx)
- `TweakSize`: 8 bytes (ipcrypt-nd tweak)
- `TweakSizeX`: 16 bytes (ipcrypt-ndx tweak)

### Functions

For every mode the `*To` variant accepts a destination buffer `dst` as its first
parameter. If `dst` is nil or too short, a new buffer is allocated automatically.
The original functions (without `To`) call the `*To` variant with a nil `dst`.

#### Deterministic Mode (ipcrypt-deterministic)

- `EncryptIPTo(dst, key []byte, ip net.IP) (net.IP, error)`: Encrypts into dst (≥ 16 bytes)
- `EncryptIP(key []byte, ip net.IP) (net.IP, error)`: Encrypts an IP address
- `DecryptIPTo(dst, key []byte, encrypted net.IP) (net.IP, error)`: Decrypts into dst (≥ 16 bytes)
- `DecryptIP(key []byte, encrypted net.IP) (net.IP, error)`: Decrypts an IP address

#### Non-Deterministic Mode (ipcrypt-nd)

- `EncryptIPNonDeterministicTo(dst []byte, ip string, key, tweak []byte) ([]byte, error)`: Encrypts into dst (≥ 24 bytes)
- `EncryptIPNonDeterministic(ip string, key, tweak []byte) ([]byte, error)`: Encrypts with 8-byte tweak
- `DecryptIPNonDeterministicTo(dst []byte, ciphertext, key []byte) (net.IP, error)`: Decrypts into dst (≥ 16 bytes)
- `DecryptIPNonDeterministic(ciphertext, key []byte) (string, error)`: Decrypts ipcrypt-nd ciphertext

#### Extended Non-Deterministic Mode (ipcrypt-ndx)

- `EncryptIPNonDeterministicXTo(dst []byte, ip string, key, tweak []byte) ([]byte, error)`: Encrypts into dst (≥ 32 bytes)
- `EncryptIPNonDeterministicX(ip string, key, tweak []byte) ([]byte, error)`: Encrypts with 16-byte tweak
- `DecryptIPNonDeterministicXTo(dst []byte, ciphertext, key []byte) (net.IP, error)`: Decrypts into dst (≥ 16 bytes)
- `DecryptIPNonDeterministicX(ciphertext, key []byte) (string, error)`: Decrypts ipcrypt-ndx ciphertext

#### Prefix-Preserving Mode (ipcrypt-pfx)

- `EncryptIPPfxTo(dst []byte, ip net.IP, key []byte) (net.IP, error)`: Encrypts into dst (≥ 16 bytes)
- `EncryptIPPfx(ip net.IP, key []byte) (net.IP, error)`: Encrypts with prefix preservation
- `DecryptIPPfxTo(dst []byte, encryptedIP net.IP, key []byte) (net.IP, error)`: Decrypts into dst (≥ 16 bytes)
- `DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error)`: Decrypts with prefix preservation

The PFX key must be exactly 32 bytes (split into two AES-128 keys internally).
The two 16-byte halves of the key must differ; passing identical halves returns an error.
For IPv4, `dst` must still be ≥ 16 bytes; the returned `net.IP` is `dst[12:16]`.

#### KIASU-BC (low-level)

- `KiasuBCEncrypt(key, tweak, block []byte) ([]byte, error)`: Encrypts a 16-byte block with KIASU-BC
- `KiasuBCDecrypt(key, tweak, block []byte) ([]byte, error)`: Decrypts a 16-byte block with KIASU-BC

### Cached Cipher Types

For repeated operations with the same key the cached cipher types are the
preferred API. Construct one with the appropriate `New*` function, then call
methods on it. The key material is expanded once and reused across calls.
All cached types are safe for concurrent use.

#### DeterministicCipher

Created via `NewDeterministicCipher(key []byte) (*DeterministicCipher, error)`.

- `EncryptIPTo(dst []byte, ip net.IP) (net.IP, error)`
- `EncryptIP(ip net.IP) (net.IP, error)`
- `DecryptIPTo(dst []byte, encrypted net.IP) (net.IP, error)`
- `DecryptIP(encrypted net.IP) (net.IP, error)`

#### NonDeterministicCipher

Created via `NewNonDeterministicCipher(key []byte) (*NonDeterministicCipher, error)`.

- `EncryptIPTo(dst []byte, ip string, tweak []byte) ([]byte, error)`
- `EncryptIP(ip string, tweak []byte) ([]byte, error)`
- `DecryptIPTo(dst []byte, ciphertext []byte) (net.IP, error)`
- `DecryptIP(ciphertext []byte) (string, error)`

#### NonDeterministicXCipher

Created via `NewNonDeterministicXCipher(key []byte) (*NonDeterministicXCipher, error)`.

- `EncryptIPTo(dst []byte, ip string, tweak []byte) ([]byte, error)`
- `EncryptIP(ip string, tweak []byte) ([]byte, error)`
- `DecryptIPTo(dst []byte, ciphertext []byte) (net.IP, error)`
- `DecryptIP(ciphertext []byte) (string, error)`

#### PfxCipher

Created via `NewPfxCipher(key []byte) (*PfxCipher, error)`.

- `EncryptIPTo(dst []byte, ip net.IP) (net.IP, error)`
- `EncryptIP(ip net.IP) (net.IP, error)`
- `DecryptIPTo(dst []byte, encryptedIP net.IP) (net.IP, error)`
- `DecryptIP(encryptedIP net.IP) (net.IP, error)`
