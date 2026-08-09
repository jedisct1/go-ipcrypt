package ipcrypt

// padTweak spreads an 8-byte tweak over the first two rows of the state.
func padTweak(dst *block, tweak []byte) {
	clear(dst[:])
	for i := 0; i < 4; i++ {
		dst[4*i] = tweak[2*i]
		dst[4*i+1] = tweak[2*i+1]
	}
}

// tweakSchedule adds the padded tweak to every round key.
// That is all KIASU-BC is: AES-128 whose round keys carry the tweak.
func tweakSchedule(dst, rk *roundKeys, padded *block) {
	for round := 0; round < 11; round++ {
		for i := 0; i < 16; i++ {
			dst[round][i] = rk[round][i] ^ padded[i]
		}
	}
}

func kiasuEncrypt(dst *block, rk *roundKeys, tweak []byte, src *block) {
	var padded block
	padTweak(&padded, tweak)
	if hardwareAES() {
		hardwareKiasuEncrypt(dst[:], rk[0][:], padded[:], src[:])
		return
	}

	var tweaked roundKeys
	tweakSchedule(&tweaked, rk, &padded)
	encryptBlock(dst, &tweaked, src)
}

func kiasuDecrypt(dst *block, rk *roundKeys, tweak []byte, src *block) {
	var padded block
	padTweak(&padded, tweak)
	if hardwareAES() {
		hardwareKiasuDecrypt(dst[:], rk[0][:], padded[:], src[:])
		return
	}

	var tweaked roundKeys
	tweakSchedule(&tweaked, rk, &padded)
	decryptBlock(dst, &tweaked, src)
}

// kiasuSchedule validates the arguments the two exported functions share and
// expands the key.
func kiasuSchedule(rk *roundKeys, dst, key, tweak, src []byte) error {
	if len(dst) < BlockSize {
		return ErrShortBuffer
	}
	if len(key) != KeySizeND {
		return ErrInvalidKeySize
	}
	if len(tweak) != TweakSize {
		return ErrInvalidTweakSize
	}
	if len(src) != BlockSize {
		return ErrInvalidBlockSize
	}
	expandKey(rk, key)
	return nil
}

// KiasuBCEncrypt encrypts one block with KIASU-BC under a 16-byte key and an
// 8-byte tweak.
// dst needs 16 bytes, and the result is dst[:16].
func KiasuBCEncrypt(dst, key, tweak, src []byte) ([]byte, error) {
	var rk roundKeys
	if err := kiasuSchedule(&rk, dst, key, tweak, src); err != nil {
		return nil, err
	}
	var in, out block
	copy(in[:], src)
	kiasuEncrypt(&out, &rk, tweak, &in)
	copy(dst[:BlockSize], out[:])
	return dst[:BlockSize], nil
}

// KiasuBCDecrypt decrypts one block with KIASU-BC under a 16-byte key and an
// 8-byte tweak.
// dst needs 16 bytes, and the result is dst[:16].
func KiasuBCDecrypt(dst, key, tweak, src []byte) ([]byte, error) {
	var rk roundKeys
	if err := kiasuSchedule(&rk, dst, key, tweak, src); err != nil {
		return nil, err
	}
	var in, out block
	copy(in[:], src)
	kiasuDecrypt(&out, &rk, tweak, &in)
	copy(dst[:BlockSize], out[:])
	return dst[:BlockSize], nil
}
