// Hardware AES-128 for the targets whose CPU has the instructions.
//
// Whether this is compiled in is decided by the C compiler's view of the
// target, so it costs nothing to ask for: on a target without AES the
// available() function is a compile-time false and the caller keeps using the
// portable implementation.
//
// x86-64 needs to be told, with -maes or -march=native. arm64 compilers that
// target ARMv8 with crypto, which includes every Apple Silicon Mac, define
// __ARM_FEATURE_AES on their own.

#include "so/builtin/builtin.h"

#if defined(so_build_arm64) && defined(__ARM_FEATURE_AES)
#define ipcrypt_aes_hw 1
#include <arm_neon.h>
#elif (defined(so_build_amd64) || defined(so_build_i386)) && defined(__AES__)
#define ipcrypt_aes_hw 2
#include <wmmintrin.h>
#else
#define ipcrypt_aes_hw 0
#endif

// ipcrypt_aes_hw_available reports whether this build has hardware AES.
static inline bool ipcrypt_aes_hw_available(void) {
    return ipcrypt_aes_hw != 0;
}

// ipcrypt_aes_hw_encrypt encrypts the block at src into dst under the eleven
// contiguous 16-byte round keys at rk. dst and src may be the same buffer.
//
// The two instruction sets split the round differently. AESE adds the round key
// and then substitutes and shifts, so it consumes rk[0..9] and the last key is
// added by hand. AESENC substitutes, shifts, mixes and then adds, so the first
// key is added by hand and it consumes rk[1..10].
static inline void ipcrypt_aes_hw_encrypt(uint8_t* dst, const uint8_t* rk,
                                          const uint8_t* src) {
#if ipcrypt_aes_hw == 1
    uint8x16_t s = vld1q_u8(src);
    for (int i = 0; i < 9; i++) {
        s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(rk + i * 16)));
    }
    s = vaeseq_u8(s, vld1q_u8(rk + 9 * 16));
    s = veorq_u8(s, vld1q_u8(rk + 10 * 16));
    vst1q_u8(dst, s);
#elif ipcrypt_aes_hw == 2
    __m128i s = _mm_loadu_si128((const __m128i*)src);
    s = _mm_xor_si128(s, _mm_loadu_si128((const __m128i*)rk));
    for (int i = 1; i < 10; i++) {
        s = _mm_aesenc_si128(s, _mm_loadu_si128((const __m128i*)(rk + i * 16)));
    }
    s = _mm_aesenclast_si128(s, _mm_loadu_si128((const __m128i*)(rk + 10 * 16)));
    _mm_storeu_si128((__m128i*)dst, s);
#else
    (void)dst;
    (void)rk;
    (void)src;
    so_panic("ipcrypt: this build has no hardware AES");
#endif
}

// ipcrypt_kiasu_hw_encrypt encrypts the block at src into dst with KIASU-BC,
// which is AES-128 with the padded tweak added to every round key. Folding the
// tweak in as the keys are loaded costs one XOR per round, against rebuilding
// the whole schedule in memory first.
static inline void ipcrypt_kiasu_hw_encrypt(uint8_t* dst, const uint8_t* rk,
                                            const uint8_t* tweak,
                                            const uint8_t* src) {
#if ipcrypt_aes_hw == 1
    uint8x16_t t = vld1q_u8(tweak);
    uint8x16_t s = vld1q_u8(src);
    for (int i = 0; i < 9; i++) {
        s = vaesmcq_u8(vaeseq_u8(s, veorq_u8(vld1q_u8(rk + i * 16), t)));
    }
    s = vaeseq_u8(s, veorq_u8(vld1q_u8(rk + 9 * 16), t));
    s = veorq_u8(s, veorq_u8(vld1q_u8(rk + 10 * 16), t));
    vst1q_u8(dst, s);
#elif ipcrypt_aes_hw == 2
    __m128i t = _mm_loadu_si128((const __m128i*)tweak);
    __m128i s = _mm_loadu_si128((const __m128i*)src);
    s = _mm_xor_si128(s, _mm_xor_si128(_mm_loadu_si128((const __m128i*)rk), t));
    for (int i = 1; i < 10; i++) {
        s = _mm_aesenc_si128(
            s, _mm_xor_si128(_mm_loadu_si128((const __m128i*)(rk + i * 16)), t));
    }
    s = _mm_aesenclast_si128(
        s, _mm_xor_si128(_mm_loadu_si128((const __m128i*)(rk + 10 * 16)), t));
    _mm_storeu_si128((__m128i*)dst, s);
#else
    (void)dst;
    (void)rk;
    (void)tweak;
    (void)src;
    so_panic("ipcrypt: this build has no hardware AES");
#endif
}

// ipcrypt_kiasu_hw_decrypt undoes ipcrypt_kiasu_hw_encrypt.
static inline void ipcrypt_kiasu_hw_decrypt(uint8_t* dst, const uint8_t* rk,
                                            const uint8_t* tweak,
                                            const uint8_t* src) {
#if ipcrypt_aes_hw == 1
    uint8x16_t t = vld1q_u8(tweak);
    uint8x16_t s = vld1q_u8(src);
    s = vaesimcq_u8(vaesdq_u8(s, veorq_u8(vld1q_u8(rk + 10 * 16), t)));
    for (int i = 1; i < 9; i++) {
        s = vaesimcq_u8(
            vaesdq_u8(s, vaesimcq_u8(veorq_u8(vld1q_u8(rk + (10 - i) * 16), t))));
    }
    s = vaesdq_u8(s, vaesimcq_u8(veorq_u8(vld1q_u8(rk + 16), t)));
    s = veorq_u8(s, veorq_u8(vld1q_u8(rk), t));
    vst1q_u8(dst, s);
#elif ipcrypt_aes_hw == 2
    __m128i t = _mm_loadu_si128((const __m128i*)tweak);
    __m128i s = _mm_loadu_si128((const __m128i*)src);
    s = _mm_xor_si128(s, _mm_xor_si128(_mm_loadu_si128((const __m128i*)(rk + 10 * 16)), t));
    for (int i = 1; i < 10; i++) {
        s = _mm_aesdec_si128(
            s, _mm_aesimc_si128(_mm_xor_si128(
                   _mm_loadu_si128((const __m128i*)(rk + (10 - i) * 16)), t)));
    }
    s = _mm_aesdeclast_si128(
        s, _mm_xor_si128(_mm_loadu_si128((const __m128i*)rk), t));
    _mm_storeu_si128((__m128i*)dst, s);
#else
    (void)dst;
    (void)rk;
    (void)tweak;
    (void)src;
    so_panic("ipcrypt: this build has no hardware AES");
#endif
}

// ipcrypt_aes_hw_decrypt decrypts the block at src into dst under the same
// encryption round keys rk that ipcrypt_aes_hw_encrypt takes. dst and src may
// be the same buffer.
//
// Decryption runs the round keys in reverse, and all but the first and last
// have to go through InvMixColumns first. That is the AESIMC instruction, so
// the inverse schedule is derived here rather than stored.
static inline void ipcrypt_aes_hw_decrypt(uint8_t* dst, const uint8_t* rk,
                                          const uint8_t* src) {
#if ipcrypt_aes_hw == 1
    uint8x16_t s = vld1q_u8(src);
    s = vaesimcq_u8(vaesdq_u8(s, vld1q_u8(rk + 10 * 16)));
    for (int i = 1; i < 9; i++) {
        s = vaesimcq_u8(vaesdq_u8(s, vaesimcq_u8(vld1q_u8(rk + (10 - i) * 16))));
    }
    s = vaesdq_u8(s, vaesimcq_u8(vld1q_u8(rk + 16)));
    s = veorq_u8(s, vld1q_u8(rk));
    vst1q_u8(dst, s);
#elif ipcrypt_aes_hw == 2
    __m128i s = _mm_loadu_si128((const __m128i*)src);
    s = _mm_xor_si128(s, _mm_loadu_si128((const __m128i*)(rk + 10 * 16)));
    for (int i = 1; i < 10; i++) {
        s = _mm_aesdec_si128(
            s, _mm_aesimc_si128(_mm_loadu_si128((const __m128i*)(rk + (10 - i) * 16))));
    }
    s = _mm_aesdeclast_si128(s, _mm_loadu_si128((const __m128i*)rk));
    _mm_storeu_si128((__m128i*)dst, s);
#else
    (void)dst;
    (void)rk;
    (void)src;
    so_panic("ipcrypt: this build has no hardware AES");
#endif
}
