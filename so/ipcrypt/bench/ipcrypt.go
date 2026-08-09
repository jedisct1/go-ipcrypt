package main

import (
	"solod.dev/so/net/netip"
	"solod.dev/so/testing"

	"github.com/jedisct1/go-ipcrypt/so/ipcrypt"
)

var benchKey = [32]byte{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
}

func BenchmarkDeterministicEncrypt(b *testing.B) {
	var c ipcrypt.DeterministicCipher
	if err := c.Init(benchKey[:16]); err != nil {
		panic(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")

	for b.Loop() {
		encrypted, err := c.EncryptIP(ip)
		if err != nil {
			panic(err)
		}
		testing.Keep(&encrypted)
	}
}

func BenchmarkDeterministicDecrypt(b *testing.B) {
	var c ipcrypt.DeterministicCipher
	if err := c.Init(benchKey[:16]); err != nil {
		panic(err)
	}
	encrypted, err := c.EncryptIP(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		panic(err)
	}

	for b.Loop() {
		decrypted, err := c.DecryptIP(encrypted)
		if err != nil {
			panic(err)
		}
		testing.Keep(&decrypted)
	}
}

func BenchmarkNDEncrypt(b *testing.B) {
	var c ipcrypt.NonDeterministicCipher
	if err := c.Init(benchKey[:16]); err != nil {
		panic(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	tweak := benchKey[:ipcrypt.TweakSize]
	var dst [ipcrypt.NDSize]byte

	for b.Loop() {
		out, err := c.EncryptIP(dst[:], ip, tweak)
		if err != nil {
			panic(err)
		}
		testing.Keep(&out)
	}
}

func BenchmarkNDDecrypt(b *testing.B) {
	var c ipcrypt.NonDeterministicCipher
	if err := c.Init(benchKey[:16]); err != nil {
		panic(err)
	}
	var dst [ipcrypt.NDSize]byte
	ciphertext, err := c.EncryptIP(dst[:], netip.MustParseAddr("192.0.2.1"), benchKey[:ipcrypt.TweakSize])
	if err != nil {
		panic(err)
	}

	for b.Loop() {
		decrypted, err := c.DecryptIP(ciphertext)
		if err != nil {
			panic(err)
		}
		testing.Keep(&decrypted)
	}
}

func BenchmarkPfxEncryptIPv6(b *testing.B) {
	var c ipcrypt.PfxCipher
	if err := c.Init(benchKey[:]); err != nil {
		panic(err)
	}
	ip := netip.MustParseAddr("2001:db8::1")

	for b.Loop() {
		encrypted, err := c.EncryptIP(ip)
		if err != nil {
			panic(err)
		}
		testing.Keep(&encrypted)
	}
}

func BenchmarkPfxEncryptIPv4(b *testing.B) {
	var c ipcrypt.PfxCipher
	if err := c.Init(benchKey[:]); err != nil {
		panic(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")

	for b.Loop() {
		encrypted, err := c.EncryptIP(ip)
		if err != nil {
			panic(err)
		}
		testing.Keep(&encrypted)
	}
}
