package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"main.go/core"
	badRand "math/rand"
)

// This is symmetric crypto

// PRP is used to mutate the IV OR to encrypt the FS for self during the setupPhase
// in the second case, the preHashkey becomes the secretValue known only by the node (also called node.secretKey currently) and the IV is actually the unencrypted FS aka RoutingInfo || EXP || sharedSymKey
// HORNET does not specify to hash the key, but it also shouldn't harm to do so.
func PRP(preHashKey, toMutate []byte) (mutated []byte, err error) {
	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(toMutate)%aes.BlockSize != 0 {
		err = errors.New("plaintext is not a multiple of the block size")
		log.Println(err)
		return nil, err
	}

	// I'm skipping an IV, because
	// 1) when mutating IV, the "plaintext" is an IV, which is random, so no need to hide patterns from there
	// 2) when encrypting the FS... well let's hope (and I have some test for this case) that as long as some bytes are not the same, the whole encrypted stuff leaks nothing.
	ivForSV := make([]byte, aes.BlockSize)

	mutated, err = ENC(preHashKey, ivForSV, toMutate, core.SecurityParameter, false)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// Yeah, appending the ivForSV doesn't work for mutating IV: IV should have a fixed size.
	// So mutating IV should 1) not use a local IV, 2) not using ENC padding
	// By the way, FS should also not be padded to 64, but stay at 48, so probably not using an IV either
	return mutated, nil
}

// PRPInverse is used by an FS creator to decrypt it during the data transmission Phase
// As PRP hashes, PRPInverse must too
func PRPInverse(secretValue, FS []byte) (decryptedFS []byte, err error) {
	// CBC sounds most suitable as a PRP function
	// https://go.dev/src/crypto/cipher/example_test.go
	if len(FS) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		log.Println(err)
		return nil, err
	}

	ivForSV := make([]byte, aes.BlockSize)
	// I'm really not sure that cutting 16 bytes out of the FS is doable ahah Should Redo this function without using an IV, and maybe do two version if needed.
	// Mutating the IV might not need a local IV. Removing the IV from FS encryption makes the system slightly vulnerable to identical FSes. That would require to get the same EXP time at the second, guessing the routing info, to try to break force the shared symKey??? low chance
	// If not, use the remaining 32 bits from R to do a mini-local IV.
	if len(FS)%aes.BlockSize != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		log.Println(err)
		return nil, err
	}

	return DEC(secretValue, ivForSV, FS, false)
}

// PRG takes a single slice (often created from a symkey and an IV in the implementation), hash it, and use it as seed to generate randomness
// This means the randomness is deterministic (repeatable), yet fully random (Pure hashing might not give fully random output)
// for better security, I could use xor of symkey and IV instead of concatenating. But as I'm hashing instead of just using as a seed, it should be fine even without.
// Some calls to PRG need to ensure that the return value is then cut down to [:BlockLength*MaxPathLength] in order to fit the protocol.
func PRG(toHash []byte) (staticRandom []byte, err error) {
	hash := sha256.Sum256(toHash)
	staticRandom = make([]byte, core.AHDRLength)
	int64FromHash := binary.BigEndian.Uint64(hash[:8])
	// using math/rand instead of crypto/rand so I can seed it. Since the hash is already pseudo random, should be good enough
	badRand.Seed(int64(int64FromHash))
	_, err = badRand.Read(staticRandom)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	// capping staticRandom to [:BlockLength*MaxPathLength] would reduce the versatility of the function, but seriously reduce the potential for bugs within onion routing context
	return staticRandom, nil
}

// ENC adds a layer to the onion. Used by the source when preparing the packet and by relays on the backward path
// usePadding is on for regular encryption, false if using from a PRP with arguments of fixed length
// Also, the padding should only be added to the core decrypted message, not while onion-encrypting!
func ENC(symKey, IV, Onion []byte, paddingFactor int, usePadding bool) (Encrypted []byte, err error) {
	hasher := sha256.New()
	hasher.Write(symKey)
	hashedKey := hasher.Sum(nil)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	/*
		Padding thoughts: as a very short DNS query could be < 32 bytes, I'm not keen on padding to 32, as it may leak a short website
		I think that padding to 64 is a decent compromise, should catch most URL length
	*/

	// intermediate calls to ENC/DEC should not use padding as perfectly padded bytes will be computed to "up-pad"
	// to the next multiple as they try to add the padding-indicator byte
	if usePadding {
		// +1 is to have the last byte indicating the padding length!
		if (len(Onion)+1)%paddingFactor != 0 {
			paddingRequired := paddingFactor - (len(Onion)+1)%paddingFactor
			paddingIncludingIndicator := make([]byte, paddingRequired+1)
			for i := range paddingIncludingIndicator {
				paddingIncludingIndicator[i] = byte(paddingRequired)
			}
			Onion = append(Onion, paddingIncludingIndicator...)
		} else {
			Onion = append(Onion, byte(0))
		}
	}

	block, err := aes.NewCipher(hashedKey)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	Encrypted = make([]byte, len(Onion))

	mode := cipher.NewCBCEncrypter(block, IV)
	mode.CryptBlocks(Encrypted, Onion)

	return Encrypted, nil
}

// DEC removes a layer from the onion. Used by relays on the forward path and by the source when receiving a reply.
// wasPadded is true for regular decryption, false if using from a PRP with arguments of fixed length
func DEC(symKey, IV, Onion []byte, wasPadded bool) (decrypted []byte, err error) {
	hasher := sha256.New()
	hasher.Write(symKey)
	hashedKey := hasher.Sum(nil)

	block, err := aes.NewCipher(hashedKey)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	// https://go.dev/src/crypto/cipher/example_test.go
	if len(Onion) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		log.Println(err)
		return nil, err
	}
	if len(Onion)%aes.BlockSize != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		log.Println(err)
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, IV)

	decrypted = make([]byte, len(Onion))
	mode.CryptBlocks(decrypted, Onion)

	// intermediate calls to ENC/DEC should not use padding as perfectly padded bytes will be computed to "up-pad"
	// to the next multiple as they try to add the padding-indicator byte
	if wasPadded {
		paddingLength := int(decrypted[len(decrypted)-1])
		padding := decrypted[len(decrypted)-1-paddingLength:]
		decrypted = decrypted[:len(decrypted)-1-paddingLength]

		for i, value := range padding {
			if int(value) != paddingLength {
				err = errors.New(fmt.Sprintf("padding values were incorrect: %v instead of %v at position %v", value, paddingLength, i))
				log.Println(err)
				return nil, err
			}
		}
	}

	return decrypted, nil
}

// MAC can take nil for Onion and not include it in the MAC computation
// It takes an Onion on the forward path (per-hop integrity), and do not take one (= nil) on the backward path (E2E integrity)
// hmac produces 32 bytes MAC, but I cut it down to (leftmost) 16 bytes.
// As made obvious from the parameters, this MAC function is conveniently tailored for the data transmission phase.
// genericHMAC is the more overall HMAC function, which is also used by Sphinx
func MAC(symKey, IV, FS, Blinded, Onion []byte) (mac []byte) {
	macContent := append(FS, Blinded...)
	if Onion != nil {
		macContent = append(macContent, Onion...)
	}
	macKey := append(symKey, IV...)
	return GenericHMAC(macKey, macContent)
}

// GenericHMAC computes an HMAC. Due to some issues of MAC modifying underlying slices,
// I am trying to have HMAC working on copies of the slices
func GenericHMAC(key, message []byte) (mac []byte) {
	// test if with those lines, I can remove the copy from onion and else => NO
	// Also, copying the key might not be needed, also test without.
	keyCopy := make([]byte, len(key))
	messageCopy := make([]byte, len(message))
	copy(keyCopy, key)
	copy(messageCopy, message)

	hmacInstance := hmac.New(sha256.New, keyCopy)
	hmacInstance.Write(messageCopy)
	mac = hmacInstance.Sum(nil)
	return mac[:core.SecurityParameter]
}
