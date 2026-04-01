package ipcrypt

import (
	"encoding/hex"
	"net"
	"testing"
)

// TestCachedDeterministic tests DeterministicCipher against top-level API.
func TestCachedDeterministic(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")

	c, err := NewDeterministicCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Parity with top-level
	want, _ := EncryptIP(key, ip)
	got, err := c.EncryptIP(ip)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Errorf("EncryptIP: got %s, want %s", got, want)
	}

	// Decrypt parity
	dec, err := c.DecryptIP(got)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Equal(ip) {
		t.Errorf("DecryptIP: got %s, want %s", dec, ip)
	}

	// To variant with pre-allocated dst
	dst := make([]byte, 16)
	gotTo, err := c.EncryptIPTo(dst, ip)
	if err != nil {
		t.Fatal(err)
	}
	if !gotTo.Equal(want) {
		t.Errorf("EncryptIPTo: got %s, want %s", gotTo, want)
	}
	if &gotTo[0] != &dst[0] {
		t.Error("EncryptIPTo: result does not point into dst")
	}

	// Reuse: multiple calls, no state bleed
	for _, ipStr := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1"} {
		ip2 := net.ParseIP(ipStr)
		want2, _ := EncryptIP(key, ip2)
		got2, err := c.EncryptIP(ip2)
		if err != nil {
			t.Fatal(err)
		}
		if !got2.Equal(want2) {
			t.Errorf("reuse %s: got %s, want %s", ipStr, got2, want2)
		}
	}
}

// TestCachedNonDeterministic tests NonDeterministicCipher against top-level API.
func TestCachedNonDeterministic(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")

	c, err := NewNonDeterministicCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Parity
	want, _ := EncryptIPNonDeterministic("0.0.0.0", key, tweak)
	got, err := c.EncryptIP("0.0.0.0", tweak)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("EncryptIP: got %x, want %x", got, want)
	}

	// Decrypt parity
	dec, err := c.DecryptIP(got)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "0.0.0.0" {
		t.Errorf("DecryptIP: got %s, want 0.0.0.0", dec)
	}

	// To variant
	dst := make([]byte, TweakSize+16)
	gotTo, err := c.EncryptIPTo(dst, "0.0.0.0", tweak)
	if err != nil {
		t.Fatal(err)
	}
	if &gotTo[0] != &dst[0] {
		t.Error("EncryptIPTo: result does not point into dst")
	}

	dstDec := make([]byte, 16)
	decIP, err := c.DecryptIPTo(dstDec, gotTo)
	if err != nil {
		t.Fatal(err)
	}
	if !decIP.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Errorf("DecryptIPTo: got %s, want 0.0.0.0", decIP)
	}
	if &decIP[0] != &dstDec[0] {
		t.Error("DecryptIPTo: result does not point into dst")
	}
}

// TestCachedNonDeterministicX tests NonDeterministicXCipher against top-level API.
func TestCachedNonDeterministicX(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")

	c, err := NewNonDeterministicXCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// Parity
	want, _ := EncryptIPNonDeterministicX("0.0.0.0", key, tweak)
	got, err := c.EncryptIP("0.0.0.0", tweak)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("EncryptIP: got %x, want %x", got, want)
	}

	// Decrypt parity
	dec, err := c.DecryptIP(got)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "0.0.0.0" {
		t.Errorf("DecryptIP: got %s, want 0.0.0.0", dec)
	}

	// To variant with dst
	dst := make([]byte, TweakSizeX+16)
	gotTo, err := c.EncryptIPTo(dst, "0.0.0.0", tweak)
	if err != nil {
		t.Fatal(err)
	}
	if &gotTo[0] != &dst[0] {
		t.Error("EncryptIPTo: result does not point into dst")
	}

	dstDec := make([]byte, 16)
	decIP, err := c.DecryptIPTo(dstDec, gotTo)
	if err != nil {
		t.Fatal(err)
	}
	if !decIP.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Errorf("DecryptIPTo: got %s, want 0.0.0.0", decIP)
	}
}

// TestCachedPfx tests PfxCipher against top-level API.
func TestCachedPfx(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")

	c, err := NewPfxCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// IPv4 parity
	ipv4 := net.ParseIP("192.0.2.1")
	wantV4, _ := EncryptIPPfx(ipv4, key)
	gotV4, err := c.EncryptIP(ipv4)
	if err != nil {
		t.Fatal(err)
	}
	if !gotV4.Equal(wantV4) {
		t.Errorf("IPv4 EncryptIP: got %s, want %s", gotV4, wantV4)
	}

	decV4, err := c.DecryptIP(gotV4)
	if err != nil {
		t.Fatal(err)
	}
	if !decV4.Equal(ipv4) {
		t.Errorf("IPv4 DecryptIP: got %s, want %s", decV4, ipv4)
	}

	// IPv4 To variant: dst[12:16]
	dst := make([]byte, 16)
	gotV4To, err := c.EncryptIPTo(dst, ipv4)
	if err != nil {
		t.Fatal(err)
	}
	if &gotV4To[0] != &dst[12] {
		t.Error("IPv4 EncryptIPTo: result does not point into dst[12:]")
	}

	// IPv6 parity
	ipv6 := net.ParseIP("2001:db8::1")
	wantV6, _ := EncryptIPPfx(ipv6, key)
	gotV6, err := c.EncryptIP(ipv6)
	if err != nil {
		t.Fatal(err)
	}
	if !gotV6.Equal(wantV6) {
		t.Errorf("IPv6 EncryptIP: got %s, want %s", gotV6, wantV6)
	}

	decV6, err := c.DecryptIP(gotV6)
	if err != nil {
		t.Fatal(err)
	}
	if !decV6.Equal(ipv6) {
		t.Errorf("IPv6 DecryptIP: got %s, want %s", decV6, ipv6)
	}

	// Reuse: multiple IPs
	for _, ipStr := range []string{"10.0.0.1", "172.16.0.1", "255.255.255.255"} {
		ip2 := net.ParseIP(ipStr)
		want2, _ := EncryptIPPfx(ip2, key)
		got2, err := c.EncryptIP(ip2)
		if err != nil {
			t.Fatal(err)
		}
		if !got2.Equal(want2) {
			t.Errorf("reuse %s: got %s, want %s", ipStr, got2, want2)
		}
	}
}

// TestCachedConstructorValidation tests that constructors reject bad keys.
func TestCachedConstructorValidation(t *testing.T) {
	if _, err := NewDeterministicCipher([]byte("short")); err == nil {
		t.Error("NewDeterministicCipher: expected error for short key")
	}
	if _, err := NewNonDeterministicCipher([]byte("short")); err == nil {
		t.Error("NewNonDeterministicCipher: expected error for short key")
	}
	if _, err := NewNonDeterministicXCipher([]byte("short")); err == nil {
		t.Error("NewNonDeterministicXCipher: expected error for short key")
	}
	if _, err := NewPfxCipher([]byte("short")); err == nil {
		t.Error("NewPfxCipher: expected error for short key")
	}

	// PFX: two halves must differ
	sameHalves := make([]byte, 32)
	copy(sameHalves[16:], sameHalves[:16])
	if _, err := NewPfxCipher(sameHalves); err == nil {
		t.Error("NewPfxCipher: expected error for identical key halves")
	}
}

// Benchmarks for cached types

func BenchmarkCachedEncryptIP(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	c, _ := NewDeterministicCipher(key)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptIPTo(dst, ip)
	}
}

func BenchmarkCachedDecryptIP(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ip := net.ParseIP("192.0.2.1")
	c, _ := NewDeterministicCipher(key)
	encrypted, _ := c.EncryptIP(ip)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptIPTo(dst, encrypted)
	}
}

func BenchmarkCachedEncryptIPNonDeterministic(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	c, _ := NewNonDeterministicCipher(key)
	dst := make([]byte, TweakSize+16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptIPTo(dst, "192.0.2.1", tweak)
	}
}

func BenchmarkCachedDecryptIPNonDeterministic(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	tweak, _ := hex.DecodeString("08e0c289bff23b7c")
	c, _ := NewNonDeterministicCipher(key)
	ct, _ := c.EncryptIP("192.0.2.1", tweak)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptIPTo(dst, ct)
	}
}

func BenchmarkCachedEncryptIPNonDeterministicX(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	c, _ := NewNonDeterministicXCipher(key)
	dst := make([]byte, TweakSizeX+16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptIPTo(dst, "192.0.2.1", tweak)
	}
}

func BenchmarkCachedDecryptIPNonDeterministicX(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	tweak, _ := hex.DecodeString("21bd1834bc088cd2b4ecbe30b70898d7")
	c, _ := NewNonDeterministicXCipher(key)
	ct, _ := c.EncryptIP("192.0.2.1", tweak)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptIPTo(dst, ct)
	}
}

func BenchmarkCachedEncryptIPPfx_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	c, _ := NewPfxCipher(key)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptIPTo(dst, ip)
	}
}

func BenchmarkCachedDecryptIPPfx_IPv4(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("192.0.2.1")
	c, _ := NewPfxCipher(key)
	encrypted, _ := c.EncryptIP(ip)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptIPTo(dst, encrypted)
	}
}

func BenchmarkCachedEncryptIPPfx_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	c, _ := NewPfxCipher(key)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.EncryptIPTo(dst, ip)
	}
}

func BenchmarkCachedDecryptIPPfx_IPv6(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
	ip := net.ParseIP("2001:db8::1")
	c, _ := NewPfxCipher(key)
	encrypted, _ := c.EncryptIP(ip)
	dst := make([]byte, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.DecryptIPTo(dst, encrypted)
	}
}
