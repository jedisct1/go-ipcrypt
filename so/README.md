# IPCrypt for Solod

This directory is an implementation of IPCrypt for [Solod](https://solod.dev/) (So), a strict subset of Go that transpiles to C11.

## Installing

```sh
go get github.com/jedisct1/go-ipcrypt/so@latest
```

```go
import "github.com/jedisct1/go-ipcrypt/so/ipcrypt"
```

The `so` command line tool is only needed to build for C:

```sh
go install solod.dev/cmd/so@latest
```

## Using it

```go
package main

import (
	"solod.dev/so/net/netip"

	"github.com/jedisct1/go-ipcrypt/so/ipcrypt"
)

func main() {
	var key [16]byte // in real code, read this from somewhere safe

	var c ipcrypt.DeterministicCipher
	if err := c.Init(key[:]); err != nil {
		panic(err)
	}

	encrypted, err := c.EncryptIP(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		panic(err)
	}

	var out [netip.MaxAddrLen]byte
	println("encrypted:", encrypted.String(out[:]))
}
```

A longer walk through the four modes is in [example/main.go](example/main.go):

```sh
so run ./example
```

## API

Addresses are `netip.Addr` values from `solod.dev/so/net/netip`.

The modes that produce more than 128 bits of output write into a buffer you own and hand back a sub-slice of it.

| Mode                  | One-shot functions                 | Cipher type               |
| --------------------- | ---------------------------------- | ------------------------- |
| ipcrypt-deterministic | `EncryptIP`, `DecryptIP`           | `DeterministicCipher`     |
| ipcrypt-nd            | `EncryptIPND`, `DecryptIPND`       | `NonDeterministicCipher`  |
| ipcrypt-ndx           | `EncryptIPNDX`, `DecryptIPNDX`     | `NonDeterministicXCipher` |
| ipcrypt-pfx           | `EncryptIPPfx`, `DecryptIPPfx`     | `PfxCipher`               |
| KIASU-BC (low level)  | `KiasuBCEncrypt`, `KiasuBCDecrypt` | n/a                       |

Every cipher type is prepared with `Init(key []byte) error` and is read-only afterwards, so one can be shared between threads.

A cipher that was never given a key, or whose `Init` failed, refuses to work and returns `ErrUninitialized` rather than quietly encrypting under an all-zero key schedule.

The one-shot functions expand the key on every call, which is fine for occasional use and wasteful in a loop.

```go
func EncryptIP(key []byte, ip netip.Addr) (netip.Addr, error)
func DecryptIP(key []byte, encrypted netip.Addr) (netip.Addr, error)

func EncryptIPND(dst, key []byte, ip netip.Addr, tweak []byte) ([]byte, error)
func DecryptIPND(key, ciphertext []byte) (netip.Addr, error)

func EncryptIPNDX(dst, key []byte, ip netip.Addr, tweak []byte) ([]byte, error)
func DecryptIPNDX(key, ciphertext []byte) (netip.Addr, error)

func EncryptIPPfx(key []byte, ip netip.Addr) (netip.Addr, error)
func DecryptIPPfx(key []byte, encrypted netip.Addr) (netip.Addr, error)
```

Sizes are available as constants:
`KeySizeDeterministic`, `KeySizeND`, `KeySizeNDX`, `KeySizePfx`, `TweakSize`, `TweakSizeX`, `BlockSize`, and the two ciphertext lengths `NDSize` (24) and `NDXSize` (32).

For the two non-deterministic modes, `dst` must hold at least `NDSize` or `NDXSize` bytes.

Passing an empty tweak makes the package draw one from the system random source, which is what you want unless you have a reason to supply your own.

Errors are sentinels compared with `==`, since Solod has neither `fmt.Errorf` nor error wrapping:
`ErrInvalidKeySize`, `ErrInvalidTweakSize`, `ErrInvalidBlockSize`, `ErrInvalidIP`, `ErrInvalidCiphertext`, `ErrShortBuffer`, `ErrKeyHalvesEqual` and `ErrUninitialized`.

The one exception is a failure to read the random source, which the two non-deterministic modes hand back as it comes from `solod.dev/so/crypto/crand`.

## Differences from the Go package

| Go package                          | So package                      |
| ----------------------------------- | ------------------------------- |
| `net.IP`, or an address as a string | `netip.Addr`                    |
| `crypto/aes`, hardware accelerated  | portable AES in this package    |
| `New*Cipher` returns a pointer      | `Init` on a value you declared  |
| allocates when `dst` is too short   | returns `ErrShortBuffer`        |
| `fmt.Errorf("%w: got %d bytes"...)` | sentinel errors only            |
| `nil` tweak means random            | empty tweak means random        |
| `EncryptIPNonDeterministic[X]`      | `EncryptIPND`, `EncryptIPNDX`   |
| argument order varies per mode      | the key comes first everywhere  |
| an `EncryptIP`/`EncryptIPTo` pair   | one function, `dst` when needed |

Decryption returns IPv4 addresses in their IPv4-mapped IPv6 form for every mode except ipcrypt-pfx, which preserves the address family by construction.

Call `Unmap` on the result to get an IPv4 address back:

```go
decrypted, err := ipcrypt.DecryptIP(key, encrypted)
original := decrypted.Unmap()
```
