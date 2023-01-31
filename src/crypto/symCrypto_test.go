package crypto

import (
	"bytes"
	"crypto/rand"
	"log"
	"main.go/core"
	"testing"
	"time"
)

// It is here easy to call PRPInverse(PRP(x)) = x and DEC(ENC(x)) = x. Also test with more layers.
// Test 2 PRG/MAC calls to make sure the randomness is static.
// To test MAC and PRG, the whole AddLayer/RemoveLayer/CreateOnion, etc should be tested.

// TestPRGSimple ensures that the PseudoRandomGenerator PRG function is both deterministic from given inputs,
// but that the output seem random from an external point of view.
func TestPRGSimple(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}
	IV2 := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV2)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV2, %v", err)
	}

	staticRandom1, err := PRG(append(symKey, IV...))
	if err != nil {
		t.Fatalf("Couldn't run PRG, %v", err)
	}

	staticRandom2, err := PRG(append(symKey, IV...))
	if err != nil {
		t.Fatalf("Couldn't run PRG, %v", err)
	}

	diffStaticRandom, err := PRG(append(symKey, IV2...))
	if err != nil {
		t.Fatalf("Couldn't run PRG, %v", err)
	}

	if bytes.Equal(diffStaticRandom, staticRandom1) {
		t.Errorf("PRG is not input dependent")
	}
	if diffStaticRandom[0] == staticRandom1[0] {
		t.Errorf("Suspicious coincidence, rerun the test as some bytes might be static even when changing the IV")
	}
	if !bytes.Equal(staticRandom1, staticRandom2) {
		t.Errorf("PRG randomness is not static")
	}
}

// TestMacNoOnion ensures that the MAC function is deterministic given the same input and takes into account all inputs in the MAC computation.
func TestMacNoOnion(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}
	FS := make([]byte, core.FSLength)
	_, err = rand.Read(FS)
	if err != nil {
		t.Fatalf("Couldn't generate a fake FS, %v", err)
	}
	// Let's assume l = 1 for this test, so that phi = "" and blinded is pure garbage
	blinded := make([]byte, (int(core.MaxPathLength)-1)*core.BlockLength)
	_, err = rand.Read(blinded)
	if err != nil {
		t.Fatalf("Couldn't generate a fake blinded, %v", err)
	}

	mac1 := MAC(symKey, IV, FS, blinded, nil)
	mac2 := MAC(symKey, IV, FS, blinded, nil)

	mac3 := MAC(symKey, IV, FS, blinded, []byte("test"))
	mac4 := MAC(symKey, IV, FS, nil, nil)
	mac5 := MAC(symKey, IV, nil, blinded, nil)
	mac6 := MAC(symKey, nil, FS, blinded, nil)
	mac7 := MAC(nil, IV, FS, blinded, nil)

	if bytes.Equal(mac1, mac3) {
		t.Errorf("MAC ignores the Onion parameter")
	}
	if bytes.Equal(mac1, mac4) {
		t.Errorf("MAC ignores the blinded parameter")
	}
	if bytes.Equal(mac1, mac5) {
		t.Errorf("MAC ignores the FS parameter")
	}
	if bytes.Equal(mac1, mac6) {
		t.Errorf("MAC ignores the symkey parameter")
	}
	if bytes.Equal(mac1, mac7) {
		t.Errorf("MAC ignores the blinded parameter")
	}

	if !bytes.Equal(mac1, mac2) {
		t.Errorf("MAC is not deterministic")
	}

}

// TestMacWithOnion ensures that the MAC function is deterministic given the same input and takes into account all inputs in the MAC computation.
func TestMacWithOnion(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}
	FS := make([]byte, core.FSLength)
	_, err = rand.Read(FS)
	if err != nil {
		t.Fatalf("Couldn't generate a fake FS, %v", err)
	}
	// Let's assume l = 1 for this test, so that phi = "" and blinded is pure garbage
	blinded := make([]byte, (int(core.MaxPathLength)-1)*core.BlockLength)
	_, err = rand.Read(blinded)
	if err != nil {
		t.Fatalf("Couldn't generate a fake blinded, %v", err)
	}

	// Pseudo realistic DNS code. However, Onion usually also include the return header and the return IV
	onion := GenerateExampleDNSBytes()

	mac1 := MAC(symKey, IV, FS, blinded, onion)
	mac2 := MAC(symKey, IV, FS, blinded, onion)

	mac3 := MAC(symKey, IV, FS, blinded, nil)
	mac4 := MAC(symKey, IV, FS, nil, onion)
	mac5 := MAC(symKey, IV, nil, blinded, onion)
	mac6 := MAC(symKey, nil, FS, blinded, onion)
	mac7 := MAC(nil, IV, FS, blinded, onion)

	if bytes.Equal(mac1, mac3) {
		t.Errorf("MAC ignores the Onion parameter")
	}
	if bytes.Equal(mac1, mac4) {
		t.Errorf("MAC ignores the blinded parameter")
	}
	if bytes.Equal(mac1, mac5) {
		t.Errorf("MAC ignores the FS parameter")
	}
	if bytes.Equal(mac1, mac6) {
		t.Errorf("MAC ignores the symkey parameter")
	}
	if bytes.Equal(mac1, mac7) {
		t.Errorf("MAC ignores the blinded parameter")
	}

	if !bytes.Equal(mac1, mac2) {
		t.Errorf("MAC is not deterministic")
	}

}

// TestEncDec1Layer ensures that DEC(ENC(x)) = x
func TestEncDec1Layer(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}

	// Pseudo realistic DNS code. However, Onion usually also include the return header and the return IV
	onion := GenerateExampleDNSBytes()

	encrypted, err := ENC(symKey, IV, onion, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt: %v", err)
	}

	decrypted, err := DEC(symKey, IV, encrypted, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt: %v", err)
	}

	if !bytes.Equal(onion, decrypted) {
		t.Fatalf("Decryption does not produce the original message")
	}
}

// TestPRPRetrieve1Layer ensures that the PRP function can be inversed. (namely PRP^-1(PRP(x)) = x)
func TestPRPRetrieve1Layer(t *testing.T) {
	secretKey := make([]byte, core.SecurityParameter)
	_, err := rand.Read(secretKey)
	if err != nil {
		log.Println("Couldn't read randomness for the secretKey")
		return
	}
	sharedKey := make([]byte, core.SecurityParameter)
	_, err = rand.Read(sharedKey)
	if err != nil {
		log.Println("Couldn't read randomness for the secretKey")
		return
	}
	FS := GenerateExampleFSWithRandomRouting(sharedKey)
	encrypted, err := PRP(secretKey, FS)
	if err != nil {
		t.Fatalf("Couldn't mutate the FS, %v", err)
	}
	decrypted, err := PRPInverse(secretKey, encrypted)
	if err != nil {
		t.Fatalf("Couldn't decrypt the FS, %v", err)
	}

	if !bytes.Equal(FS, decrypted) {
		t.Errorf("Decryption does not produce the original FS")
	}
}

// TestPRPShouldBeStatic should be static actually for IV mutations, there shouldn't be a random permutation IV messing things up.
func TestPRPShouldBeStatic(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}
	IV2 := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV2)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV2, %v", err)
	}

	mutated1, err := PRP(symKey, IV)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV, %v", err)
	}
	mutated2, err := PRP(symKey, IV)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV, %v", err)
	}
	diffMutated, err := PRP(symKey, IV2)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV2, %v", err)
	}

	if bytes.Equal(diffMutated, mutated1) {
		t.Errorf("PRG is not input dependent")
	}
	if diffMutated[0] == mutated1[0] {
		t.Errorf("Suspicious coincidence, rerun the test as some bytes might be static even when changing the IV")
	}
	if !bytes.Equal(mutated1, mutated2) {
		t.Errorf("PRP mutation is not static")
	}

}

// TestPRPWithFSShouldBeStatic should be static actually for FS as well, as I'm not intending on adding another IV to the packets.
func TestPRPWithFSShouldBeStatic(t *testing.T) {
	sharedKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(sharedKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating secretKey, %v", err)
	}
	secretKey := make([]byte, core.SecurityParameter)
	bytesAmount, err = rand.Read(secretKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating secretKey, %v", err)
	}
	FS := GenerateExampleFSWithRandomRouting(sharedKey)
	time.Sleep(5 * time.Second) // Sleep so that the EXP of the FS is not the same
	FS2 := GenerateExampleFSWithRandomRouting(sharedKey)

	mutated1, err := PRP(secretKey, FS)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV, %v", err)
	}
	mutated2, err := PRP(secretKey, FS)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV, %v", err)
	}
	diffMutated, err := PRP(secretKey, FS2)
	if err != nil {
		t.Fatalf("Couldn't mutate the IV2, %v", err)
	}

	if bytes.Equal(diffMutated, mutated1) {
		t.Errorf("PRG is not input dependent")
	}
	if diffMutated[0] == mutated1[0] {
		t.Errorf("Suspicious coincidence, rerun the test as some bytes might be static even when changing the IV")
	}
	if !bytes.Equal(mutated1, mutated2) {
		t.Errorf("PRP mutation is not static")
	}

}

// TestEncDec3Layer ensures that DEC(DEC(DEC(ENC(ENC(ENC(x)))))) = x. This is especially required in the context of onion encryption.
func TestEncDec3Layer(t *testing.T) {
	symKey := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(symKey)
	if err != nil || bytesAmount != core.SecurityParameter {
		t.Fatalf("Error while generating random SymKeys, %v", err)
	}
	IV := make([]byte, core.SecurityParameter)
	_, err = rand.Read(IV)
	if err != nil {
		t.Fatalf("Couldn't read randomness for IV, %v", err)
	}
	// Pseudo realistic DNS code. However, Onion usually also include the return header and the return IV
	onion := GenerateExampleDNSBytes()

	encrypted1, err := ENC(symKey, IV, onion, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt: %v", err)
	}
	encrypted2, err := ENC(symKey, IV, encrypted1, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt: %v", err)
	}
	encrypted3, err := ENC(symKey, IV, encrypted2, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt: %v", err)
	}

	decrypted3, err := DEC(symKey, IV, encrypted3, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt: %v", err)
	}
	decrypted2, err := DEC(symKey, IV, decrypted3, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt: %v", err)
	}
	decrypted1, err := DEC(symKey, IV, decrypted2, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt: %v", err)
	}

	if !bytes.Equal(onion, decrypted1) {
		t.Errorf("Decryption does not produce the original message after 3 layers")
	}
}

// TestPRPRetrieve3Layer could be implemented, but is already confirmed to work correctly by higher-level tests
func TestPRPRetrieve3Layer(t *testing.T) {

}
