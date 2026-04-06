package crypto

import (
	"GoClient/discovery"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var (
	dhP *big.Int
	dhAlpha *big.Int
)

func init() {
	// 2048-bit safe prime from RFC 3526
	pHex := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	dhP, _ = new(big.Int).SetString(pHex, 16)
	dhAlpha = big.NewInt(2)
}

// generateDHExponent returns a cryptographically random private exponent.
func GenerateDHExponent() (*big.Int, error) {
	// Pick a cryptographically secure random value in [2, p-2]
	max := new(big.Int).Sub(dhP, big.NewInt(2))
	a, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(a, big.NewInt(2)), nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
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

func Decrypt(key, ciphertext []byte) ([]byte, error) {
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

func CreateChallenge() ([]byte, error) {
	n := make([]byte, 16)
	_, err := rand.Read(n)
	return n, err
}

func BytesToBigInt(data []byte) (*big.Int, error) {
	return new(big.Int).SetBytes(data), nil

}

func BigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

func deriveKeyFromPassphrase(password string, salt []byte) []byte {
    return pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
}

func DeriveEKEKey(password, peerA, peerB string) ([]byte) {
    nameA, nameB := peerA, peerB
    if nameA > nameB {
        nameA, nameB = nameB, nameA
    }

    combined := nameA + ":" + nameB
	fmt.Printf("COMBINED: %s\n\n\n", combined)
    saltHash := sha256.Sum256([]byte(combined))
    salt := saltHash[:16]

    return deriveKeyFromPassphrase(password, salt)
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(data)
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(data)
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return pub.(*rsa.PublicKey), nil
}

var pssOptions = &rsa.PSSOptions{
    SaltLength: rsa.PSSSaltLengthEqualsHash,
    Hash:       crypto.SHA256,
}

func rsaPssSign(privKey *rsa.PrivateKey, data []byte) (string, error) {
    hash := sha256.Sum256(data)
    sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hash[:], pssOptions)
    if err != nil {
        return "", fmt.Errorf("failed to sign: %w", err)
    }
    return base64.StdEncoding.EncodeToString(sig), nil
}

func rsaPssVerify(pubKey *rsa.PublicKey, data []byte, b64Sig string) error {
    sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
    if err != nil {
        return fmt.Errorf("invalid base64 signature: %w", err)
    }

    hash := sha256.Sum256(data)
    return rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], sigBytes, pssOptions)
}

func publicKeyToBase64(pub *rsa.PublicKey) (string, error) {
    der, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(der), nil
}

type StsState struct {
	myDhExp *big.Int
	myDhValue *big.Int
	K []byte
	myPrivKey *rsa.PrivateKey
	peerPubKey *rsa.PublicKey
}

func NewStsState(peerName string) (*StsState, error) {
	newStsState := &StsState{}

	exp, err := GenerateDHExponent(); if err != nil {
		return nil, err
	}
	newStsState.myDhExp = exp

	myDhValue := new(big.Int).Exp(dhAlpha, exp, dhP)

	newStsState.myDhValue = myDhValue

	myPrivKey, err := loadPrivateKey("keys/private.pem"); if err != nil {
		return nil, err
	}

	newStsState.myPrivKey = myPrivKey

	peerPubKeys, err := discovery.LoadPeerKeys("keys/peer_pub_keys.json"); if err != nil {
		return nil, err
	}

	peerPubKey := peerPubKeys[peerName]
	if peerPubKey == nil {
		return nil, fmt.Errorf("Peer %s does not have an associated RSA PubKey stored", peerName)
	}

	newStsState.peerPubKey = peerPubKey
	return newStsState, nil
}

func (s *StsState) BuildSTSMessage2Values(peerDhValue []byte) ([]byte, []byte, error){
	myDhValueAsBytes := BigIntToBytes(s.myDhValue)
	concatenatedDhValues := append(myDhValueAsBytes, peerDhValue...);
	signature, err := rsaPssSign(s.myPrivKey, concatenatedDhValues); if err != nil {
		return nil, nil, err
	}

	if s.K == nil {
		return nil, nil, fmt.Errorf("Attempted to build STS Message 2 without K set")
	}

	encryptedSignature, err := Encrypt(s.K, []byte(signature)); if err != nil {
		return nil, nil, err
	}

	return myDhValueAsBytes, encryptedSignature, nil
}

func (s *StsState) deriveK(peerDhValue []byte) error {
	peerDhBigInt, err := BytesToBigInt(peerDhValue); if err != nil {
		return err
	}

	myExp := s.myDhExp
	combinedDh := new(big.Int).Exp(peerDhBigInt, myExp, dhP).Bytes()
	k := sha256.Sum256(combinedDh)
	s.K = k[:]	
	return nil
}

type PakeState struct {
	w    []byte
	a    *big.Int
	b    *big.Int
	K    []byte
	rA   []byte
	rB   []byte
	myPubKey *rsa.PublicKey
}

func NewPakeState(password string, peerA string, peerB string) (*PakeState, error) {
	newPakeState := &PakeState{}
	newPakeState.w = DeriveEKEKey(password, peerA, peerB)
	myPubKey, err := loadPublicKey("keys/public.pem"); if err != nil {
		return nil, err
	}
	newPakeState.myPubKey = myPubKey
	return newPakeState, nil
}


func (p *PakeState) DecryptW(ciphertext []byte) ([]byte, error) {
	return Decrypt(p.w, ciphertext)
}

func (p *PakeState) DecryptK(ciphertext []byte) ([]byte, error) {
	return Decrypt(p.K, ciphertext)
}

func (p *PakeState) EncryptW(plaintext []byte) ([]byte, error) {
	return Encrypt(p.w, plaintext)
}

func (p *PakeState) EncryptK(plaintext []byte) ([]byte, error) {
	return Encrypt(p.K, plaintext)
}

func (p *PakeState) GenerateB() {
	exp, _ := GenerateDHExponent()
	//HANDLE LATER
	p.b = exp
}

func (p *PakeState) GenerateA() {
	exp, _ := GenerateDHExponent()
	//HANDLE LATER
	p.a = exp
}

func (p *PakeState) GenerateRB() {
	chal, _ := CreateChallenge()
	// Handle Later
	p.rB = chal
}

func (p *PakeState) GenerateRA() {
	chal, _ := CreateChallenge()
	// Handle Later
	p.rA = chal
}

func (p *PakeState) DeriveK(peerDhValue []byte) {
	peerDhBigInt, _ := BytesToBigInt(peerDhValue)
	// Handle Later
	myExp := p.b
	fmt.Printf("MY EXP: %s", myExp)
	if p.b == nil {
	    myExp = p.a
		fmt.Printf("MY EXP: %s", myExp)
	}
	combinedDh := new(big.Int).Exp(peerDhBigInt, myExp, dhP).Bytes()
	k := sha256.Sum256(combinedDh)
	p.K = k[:]
}

func (p *PakeState) BuildC1() []byte {
	P1 := BigIntToBytes(new(big.Int).Exp(dhAlpha, p.a, dhP))
	C1, _ := p.EncryptW(P1)

	return C1
}

func (p *PakeState) BuildC2_C3() ([]byte, []byte) {
	P2 := BigIntToBytes(new(big.Int).Exp(dhAlpha, p.b, dhP))
	C2, _ := p.EncryptW(P2)
	fmt.Printf("\n\n\n\nSENT rB: %s\n\n\n\n", p.rB)
	C3, _ := p.EncryptK(p.rB)

	return C2, C3
}

func (p *PakeState) BuildC4(rB []byte) ([]byte, error) {
	P4 := append(p.rA, rB...);
	myBase64PubKey, err := publicKeyToBase64(p.myPubKey); if err != nil {
		return nil, err
	}
	P4 = append(P4, []byte(myBase64PubKey)...)
	C4, _ := p.EncryptK(P4)
	return C4, nil
}

func (p *PakeState) BuildC5(recveivedRA []byte) ([]byte, error) {
	myBase64PubKey, err := publicKeyToBase64(p.myPubKey); if err != nil {
		return nil, err
	}
	P5 := append(recveivedRA, []byte(myBase64PubKey)...);
	C5, err := p.EncryptK(P5); if err != nil {
		return nil, err
	}
	return C5, nil
}

func (p *PakeState) ValidateRB(peerRB []byte) bool {
	return bytes.Equal(peerRB, p.rB)
}


func (p *PakeState) ValidateRA(peerRA []byte) bool {
	return bytes.Equal(peerRA, p.rA)
}