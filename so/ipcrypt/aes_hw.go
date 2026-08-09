package ipcrypt

// The So transpiler reads this marker and embeds the header into the generated
// C; Go itself has no use for it.
//
//so:embed aes_hw.h
//lint:ignore U1000 marker for the transpiler
var aes_hw_h string

// hardwareAES reports whether this build has AES instructions.
// It is a compile-time constant in C, so the branch it guards costs nothing and
// the unused path is dropped.
// The Go toolchain never takes it, which is why `go test` always covers the
// portable implementation.
//
//so:extern ipcrypt_aes_hw_available
func hardwareAES() bool { return false }

// hardwareEncryptBlock encrypts src into dst under the eleven contiguous
// 16-byte round keys at rk.
//
//so:extern ipcrypt_aes_hw_encrypt
func hardwareEncryptBlock(dst, rk, src []byte) {
	panic("ipcrypt: this build has no hardware AES")
}

// hardwareDecryptBlock decrypts src into dst under the same round keys
// hardwareEncryptBlock takes.
//
//so:extern ipcrypt_aes_hw_decrypt
func hardwareDecryptBlock(dst, rk, src []byte) {
	panic("ipcrypt: this build has no hardware AES")
}

// hardwareKiasuEncrypt encrypts src into dst with KIASU-BC, adding the padded
// tweak to each round key as it is loaded.
//
//so:extern ipcrypt_kiasu_hw_encrypt
func hardwareKiasuEncrypt(dst, rk, tweak, src []byte) {
	panic("ipcrypt: this build has no hardware AES")
}

// hardwareKiasuDecrypt undoes hardwareKiasuEncrypt.
//
//so:extern ipcrypt_kiasu_hw_decrypt
func hardwareKiasuDecrypt(dst, rk, tweak, src []byte) {
	panic("ipcrypt: this build has no hardware AES")
}
