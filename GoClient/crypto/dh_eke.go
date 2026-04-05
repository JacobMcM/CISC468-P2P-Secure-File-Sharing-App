package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
)

// ── Diffie-Hellman group (RFC 3526 – 2048-bit MODP Group 14) ─────────────────

var (
	dhP *big.Int // safe prime
	dhAlpha *big.Int // generator α = 2
	dhW string
)

func init() {
	// 2048-bit safe prime from RFC 3526 §3
	pHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	dhP, _ = new(big.Int).SetString(pHex, 16)
	dhAlpha = big.NewInt(2)
	dhW = "password"
}

// generateDHExponent returns a cryptographically random private exponent.
func generateDHExponent() (*big.Int, error) {
	// Pick a cryptographically secure random value in [2, p-2]
	max := new(big.Int).Sub(dhP, big.NewInt(2))
	a, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(a, big.NewInt(2)), nil
}

// encrypt seals plaintext with AES-256-GCM under key.
// Output layout: [12-byte nonce | ciphertext+tag].
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return ct, nil
}

// decrypt opens an AES-256-GCM ciphertext produced by encrypt.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}

func createChallenge() ([]byte, error) {
	n := make([]byte, 32)
	_, err := rand.Read(n)
	return n, err
}

func bytesToBigInt(data []byte) (*big.Int, error) {
	return new(big.Int).SetBytes(data), nil

}

func bigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

func deriveKey(src []byte) []byte {
	h := sha256.Sum256(src)
	return h[:]
}


// Alice holds all of Alice's ephemeral state.
type Alice struct {
	wKey []byte   // key derived from preshared password
	a    *big.Int // DH private exponent
	K    []byte   // session key
	rA   []byte   // Alice's challenge nonce
}

// Bob holds all of Bob's ephemeral state.
type Bob struct {
	wKey []byte
	b    *big.Int
	K    []byte
	rB   []byte
}

type PakeState struct {
	w    []byte
	a    *big.Int
	b    *big.Int
	K    []byte
	rA   []byte
	rB   []byte
}

// NewPakeState creates a fresh handshake state with the preshared password
func NewPakeState(password []byte) *PakeState {
	var err error

	newPakeState := &PakeState{}
	newPakeState.w = deriveKey(password)

	newPakeState.a, err = generateDHExponent()
	if err != nil { panic(fmt.Sprintf("generateDHExponent failed: %v", err)) }

	return newPakeState
}

func (p *PakeState) AuthenticateAsClient(conn net.Conn) error {

	// send enc_w(alpha^a) to server
	P1 := bigIntToBytes(new(big.Int).Exp(dhAlpha, p.a, dhP))
	C1, err := encrypt(p.w, P1)
	if err != nil { 
		panic(fmt.Sprintf("encrypt C1 failed: %v", err)) 
	}
	sendMsg(conn, C1)
	fmt.Printf("Sent C1 to %s\n", conn.RemoteAddr())

	// Receive C2 = enc_w(alpha^b), C3 = enc_K(r_b)
	C2, err := recvMsg(conn)
	if err != nil {
		panic(fmt.Sprintf("Recv C2 failed: %v", err))
	}

	C3, err := recvMsg(conn)
	if err != nil {
		panic(fmt.Sprintf("Recv C3 failed: %v", err))
	}

	P2_bytes, _ := decrypt(p.w, C2);
	P2_bigInt, _ := bytesToBigInt(P2_bytes);

	// Calculate K as alpha^ba
	p.K = deriveKey(new(big.Int).Exp(P2_bigInt, p.a, dhP).Bytes());

	P3_bytes, _ := decrypt(p.K, C3);
	p.rA, _ = createChallenge();

	P4 := append(p.rA, P3_bytes...);
	C4, _ := encrypt(p.K, P4);
	sendMsg(conn, C4)
	fmt.Printf("Sent C4 to Bob! Length: %d\n", len(C4))

	// Receive server's challenge response and verify
	C5, err := recvMsg(conn)
	P5_bytes, _ := decrypt(p.K, C5);

	if bytes.Equal(p.rA, P5_bytes) {
		fmt.Printf("rA Validated!\n")
	} else {
		fmt.Printf("rA validation failed!!!\n")
	}
	return nil
}


func (p *PakeState) AuthenticateAsServer(conn net.Conn) error {
	C1, err := recvMsg(conn)

	if err != nil {
		panic(fmt.Sprintf("Recv C1 failed: %v", err))
	}

	//Step 4
	P1_bytes, err := decrypt(p.w, C1)
	if err != nil { panic(fmt.Sprintf("decrypt C1 failed: %v", err)) }
	P1_bigInt, err := bytesToBigInt(P1_bytes)
	if err != nil { panic(fmt.Sprintf("bytesToBigInt failed: %v", err)) }
	p.b, err = generateDHExponent()
	if err != nil { panic(fmt.Sprintf("generateDHExponent failed: %v", err)) }
	p.rB, err = createChallenge()
	if err != nil { panic(fmt.Sprintf("createChallenge failed: %v", err)) }
	p.K = deriveKey(new(big.Int).Exp(P1_bigInt, p.b, dhP).Bytes())

	//Step 5
	P2 := bigIntToBytes(new(big.Int).Exp(dhAlpha, p.b, dhP));
	C2, _ := encrypt(p.w, P2)
	C3, err := encrypt(p.K, p.rB)
	if err != nil {
		panic(fmt.Sprintf("enc C3 failed: %v", err)) 
	}
	sendMsg(conn, C2)
	sendMsg(conn, C3)
	fmt.Printf("Sent C2, C3 to Alice! Length C2: %d, Length C3: %d\n", len(C2), len(C3))

	//Step 8 
	C4, err := recvMsg(conn)
	if err != nil {
		panic(fmt.Sprintf("Recv C4 failed: %v", err))
	}

	P4_bytes, _ := decrypt(p.K, C4);
	rA := P4_bytes[:32]
	rB := P4_bytes[32:]

	//Step 9
	C5, _ := encrypt(p.K, rA);
	sendMsg(conn, C5);
	fmt.Printf("Sent C5 to Alice! Length: %d\n", len(C5));

	if bytes.Equal(rB, p.rB) {
		fmt.Printf("rB Validated!\n")
	} else {
		fmt.Printf("rB validation failed!!!\n")
		panic("VALIDATION FAILED");
	}

	return nil
}




func sendMsg(conn net.Conn, data []byte) error {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	if _, err := conn.Write(length); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func recvMsg(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}
// SessionKey returns the derived session key after a successful handshake
// returns nil if handshake hasn't completed
// func (p *PakeState) SessionKey() []byte

func Main() {
	password_string := []byte("password") // Step 1: preshared OOB
	password := deriveKey(password_string)

	alice := &Alice{}
	bob := &Bob{}

	// Step 2
	var err error

	alice.a, err = generateDHExponent()
	if err != nil { panic(fmt.Sprintf("generateDHExponent failed: %v", err)) }

	//Step 3
	P1 := bigIntToBytes(new(big.Int).Exp(dhAlpha, alice.a, dhP))
	C1, err := encrypt(password, P1)
	if err != nil { panic(fmt.Sprintf("encrypt C1 failed: %v", err)) }
	fmt.Printf("Sent C1 to Bob! Length %d\n", len(C1))

	//Step 4
	P1_bytes, err := decrypt(password, C1)
	if err != nil { panic(fmt.Sprintf("decrypt C1 failed: %v", err)) }
	P1_bigInt, err := bytesToBigInt(P1_bytes)
	if err != nil { panic(fmt.Sprintf("bytesToBigInt failed: %v", err)) }
	bob.b, err = generateDHExponent()
	if err != nil { panic(fmt.Sprintf("generateDHExponent failed: %v", err)) }
	bob.rB, err = createChallenge()
	if err != nil { panic(fmt.Sprintf("createChallenge failed: %v", err)) }
	bob.K = deriveKey(new(big.Int).Exp(P1_bigInt, bob.b, dhP).Bytes())

	//Step 5
	P2 := bigIntToBytes(new(big.Int).Exp(dhAlpha, bob.b, dhP));
	C2, _ := encrypt(password, P2)
	C3, err := encrypt(bob.K, bob.rB)
	if err != nil {
		panic(fmt.Sprintf("enc C3 failed: %v", err)) 
	}
	fmt.Printf("Sent C2, C3 to Alice! Length C2: %d, Length C3: %d\n", len(C2), len(C3))

	//Step 6
	P2_bytes, _ := decrypt(password, C2);
	P2_bigInt, _ := bytesToBigInt(P2_bytes);
	alice.K = deriveKey(new(big.Int).Exp(P2_bigInt, alice.a, dhP).Bytes())
	P3_bytes, _ := decrypt(alice.K, C3);
	alice.rA, _ = createChallenge();

	//Step 7
	P4 := append(alice.rA, P3_bytes...);
	C4, _ := encrypt(alice.K, P4);
	fmt.Printf("Sent C4 to Bob! Length: %d\n", len(C4))

	//Step 8 
	P4_bytes, _ := decrypt(bob.K, C4);
	rA := P4_bytes[:32]
	rB := P4_bytes[32:]

	if bytes.Equal(rB, bob.rB) {
		fmt.Printf("rB Validated!\n")
	} else {
		fmt.Printf("rB validation failed!!!\n")
	}

	//Step 9
	C5, _ := encrypt(bob.K, rA);
	fmt.Printf("Sent C5 to Alice! Length: %d\n", len(C5));

	//Step 10
	P5_bytes, _ := decrypt(alice.K, C5);

	if bytes.Equal(alice.rA, P5_bytes) {
		fmt.Printf("rA Validated!\n")
	} else {
		fmt.Printf("rA validation failed!!!\n")
	}

	if bytes.Equal(alice.K, bob.K) {
		fmt.Printf("KEYS MATCH\n")
	}
}
