package wasmengine

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"strings"

	sockcastv1 "github.com/theraphim/sockcast-proto/gen/go/sockcast/v1"
)

const (
	sshMsgUserauthRequest = 50
	opensshAuthMagic      = "openssh-key-v1\x00"

	sshAgentRSASHA2_256 = 2
	sshAgentRSASHA2_512 = 4
)

var (
	ErrPassphraseRequired = errors.New("SSH private key is encrypted; a passphrase is required")
	ErrInvalidPassphrase  = errors.New("invalid passphrase or corrupted SSH private key")
)

type LoadedSshKey struct {
	SigningKey ed25519.PrivateKey
	RSAKey     *rsa.PrivateKey
	PublicKey  *sockcastv1.PublicKey
}

func readU32(cursor *[]byte) (uint32, bool) {
	if len(*cursor) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32((*cursor)[:4])
	*cursor = (*cursor)[4:]
	return v, true
}

func readBytes(cursor *[]byte) ([]byte, bool) {
	n, ok := readU32(cursor)
	if !ok || uint32(len(*cursor)) < n {
		return nil, false
	}
	out := (*cursor)[:n]
	*cursor = (*cursor)[n:]
	return out, true
}

func readString(cursor *[]byte) (string, bool) {
	b, ok := readBytes(cursor)
	if !ok {
		return "", false
	}
	return string(b), true
}

func readMpint(cursor *[]byte) (*big.Int, bool) {
	b, ok := readBytes(cursor)
	if !ok {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}

func writeSSHBytes(buf []byte, data []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	buf = append(buf, lenBuf[:]...)
	return append(buf, data...)
}

func writeSSHString(buf []byte, s string) []byte {
	return writeSSHBytes(buf, []byte(s))
}

func writeSSHMpint(buf []byte, n *big.Int) []byte {
	if n.Sign() == 0 {
		return writeSSHBytes(buf, nil)
	}
	b := n.Bytes()
	if len(b) > 0 && (b[0]&0x80) != 0 {
		b = append([]byte{0x00}, b...)
	}
	return writeSSHBytes(buf, b)
}

func encodeRSAPublicKeyBlob(pub *rsa.PublicKey) []byte {
	var blob []byte
	blob = writeSSHString(blob, "ssh-rsa")
	blob = writeSSHMpint(blob, big.NewInt(int64(pub.E)))
	blob = writeSSHMpint(blob, pub.N)
	return blob
}

func ParsePublicKeyBlob(keyBlob []byte, comment string) *sockcastv1.PublicKey {
	cursor := keyBlob
	keyType, ok := readString(&cursor)
	if !ok {
		keyType = "unknown"
	}
	digest := sha256.Sum256(keyBlob)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	return &sockcastv1.PublicKey{
		KeyBlob:           append([]byte(nil), keyBlob...),
		Comment:           comment,
		KeyType:           keyType,
		FingerprintSha256: fp,
	}
}

func ParseSshAuthContext(data []byte) *sockcastv1.SshAuthContext {
	cursor := data
	sessionID, ok := readBytes(&cursor)
	if !ok || len(cursor) == 0 || cursor[0] != sshMsgUserauthRequest {
		return &sockcastv1.SshAuthContext{IsUserauthRequest: false}
	}
	cursor = cursor[1:]
	username, ok := readString(&cursor)
	if !ok {
		return &sockcastv1.SshAuthContext{IsUserauthRequest: false}
	}
	serviceName, ok := readString(&cursor)
	if !ok {
		return &sockcastv1.SshAuthContext{IsUserauthRequest: false}
	}
	method, ok := readString(&cursor)
	if !ok || method != "publickey" || len(cursor) == 0 {
		return &sockcastv1.SshAuthContext{IsUserauthRequest: false}
	}
	cursor = cursor[1:] // has_signature boolean
	algo, ok := readString(&cursor)
	if !ok {
		return &sockcastv1.SshAuthContext{IsUserauthRequest: false}
	}
	return &sockcastv1.SshAuthContext{
		IsUserauthRequest: true,
		TargetUsername:    username,
		ServiceName:       serviceName,
		PubkeyAlgorithm:   algo,
		SessionId:         append([]byte(nil), sessionID...),
	}
}

func ParseOpenSSHPEM(pemStr string, passphrase string, hasPassphrase bool) (*LoadedSshKey, error) {
	trimmedPem := strings.TrimSpace(pemStr)
	if strings.Contains(trimmedPem, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(trimmedPem, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(trimmedPem, "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		return parseClassicPEMPrivateKey(trimmedPem, passphrase, hasPassphrase)
	}

	var b64Body strings.Builder
	inBody := false
	foundEnd := false
	for _, line := range strings.Split(pemStr, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "-----BEGIN OPENSSH PRIVATE KEY-----" {
			inBody = true
			continue
		}
		if trimmed == "-----END OPENSSH PRIVATE KEY-----" {
			if inBody {
				foundEnd = true
				break
			}
		}
		if inBody && trimmed != "" {
			b64Body.WriteString(trimmed)
		}
	}
	if !inBody || !foundEnd {
		return nil, errors.New("invalid SSH private key format: expected OPENSSH PRIVATE KEY, RSA PRIVATE KEY, or PRIVATE KEY PEM")
	}

	raw, err := base64.StdEncoding.DecodeString(b64Body.String())
	if err != nil {
		return nil, fmt.Errorf("invalid OpenSSH private key base64: %w", err)
	}
	if !bytes.HasPrefix(raw, []byte(opensshAuthMagic)) {
		return nil, errors.New("invalid OpenSSH private key: missing openssh-key-v1 header")
	}
	cursor := raw[len(opensshAuthMagic):]
	ciphername, ok1 := readString(&cursor)
	kdfname, ok2 := readString(&cursor)
	kdfoptions, ok3 := readBytes(&cursor)
	numKeys, ok4 := readU32(&cursor)
	_, ok5 := readBytes(&cursor)
	encryptedPriv, ok6 := readBytes(&cursor)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return nil, errors.New("invalid OpenSSH private key: truncated outer fields")
	}
	if numKeys != 1 {
		return nil, fmt.Errorf("expected 1 key in OpenSSH private key, found %d", numKeys)
	}

	var decrypted []byte
	switch ciphername {
	case "none":
		if kdfname != "none" {
			return nil, fmt.Errorf("unsupported OpenSSH KDF %q", kdfname)
		}
		decrypted = encryptedPriv
	default:
		if !hasPassphrase || passphrase == "" {
			return nil, ErrPassphraseRequired
		}
		decrypted, err = decryptOpenSSHPrivateSection(ciphername, kdfname, kdfoptions, passphrase, encryptedPriv)
		if err != nil {
			return nil, err
		}
	}

	privCursor := decrypted
	check1, ok1 := readU32(&privCursor)
	check2, ok2 := readU32(&privCursor)
	if !ok1 || !ok2 || check1 != check2 {
		if ciphername == "none" {
			return nil, errors.New("corrupted OpenSSH private key (checkint mismatch)")
		}
		return nil, ErrInvalidPassphrase
	}
	keyType, ok := readString(&privCursor)
	if !ok {
		return nil, errors.New("truncated key_type in private section")
	}

	switch keyType {
	case "ssh-ed25519":
		pubBytes, ok1 := readBytes(&privCursor)
		privBytes, ok2 := readBytes(&privCursor)
		comment, ok3 := readString(&privCursor)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("truncated ed25519 key fields")
		}
		if len(pubBytes) != 32 || len(privBytes) != 64 {
			return nil, errors.New("invalid ed25519 key lengths")
		}
		privKey := ed25519.NewKeyFromSeed(privBytes[:32])
		derivedPub := privKey.Public().(ed25519.PublicKey)
		if !bytes.Equal(derivedPub, pubBytes) || !bytes.Equal(privBytes[32:], pubBytes) {
			return nil, errors.New("ed25519 public key does not match private key seed")
		}
		var keyBlob []byte
		keyBlob = writeSSHString(keyBlob, "ssh-ed25519")
		keyBlob = writeSSHBytes(keyBlob, pubBytes)
		return &LoadedSshKey{
			SigningKey: privKey,
			PublicKey:  ParsePublicKeyBlob(keyBlob, comment),
		}, nil

	case "ssh-rsa":
		n, ok1 := readMpint(&privCursor)
		e, ok2 := readMpint(&privCursor)
		d, ok3 := readMpint(&privCursor)
		_, ok4 := readMpint(&privCursor) // iqmp
		p, ok5 := readMpint(&privCursor)
		q, ok6 := readMpint(&privCursor)
		comment, ok7 := readString(&privCursor)
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
			return nil, errors.New("truncated ssh-rsa key fields in OpenSSH private key")
		}
		rsaPriv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: n,
				E: int(e.Int64()),
			},
			D:      d,
			Primes: []*big.Int{p, q},
		}
		rsaPriv.Precompute()
		if err := rsaPriv.Validate(); err != nil {
			return nil, fmt.Errorf("invalid ssh-rsa private key parameters: %w", err)
		}
		keyBlob := encodeRSAPublicKeyBlob(&rsaPriv.PublicKey)
		return &LoadedSshKey{
			RSAKey:    rsaPriv,
			PublicKey: ParsePublicKeyBlob(keyBlob, comment),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported SSH key type %q (supported: ssh-ed25519, ssh-rsa)", keyType)
	}
}

func parseClassicPEMPrivateKey(pemStr string, passphrase string, hasPassphrase bool) (*LoadedSshKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	der := block.Bytes
	if procType := block.Headers["Proc-Type"]; strings.Contains(procType, "ENCRYPTED") {
		if !hasPassphrase || passphrase == "" {
			return nil, ErrPassphraseRequired
		}
		var err error
		der, err = decryptLegacyPEMBlock(block, passphrase)
		if err != nil {
			return nil, err
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaPriv, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			if block.Headers["Proc-Type"] != "" {
				return nil, ErrInvalidPassphrase
			}
			return nil, fmt.Errorf("failed to parse PKCS#1 RSA private key: %w", err)
		}
		rsaPriv.Precompute()
		keyBlob := encodeRSAPublicKeyBlob(&rsaPriv.PublicKey)
		return &LoadedSshKey{
			RSAKey:    rsaPriv,
			PublicKey: ParsePublicKeyBlob(keyBlob, "rsa-pem-key"),
		}, nil

	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		switch k := parsed.(type) {
		case *rsa.PrivateKey:
			k.Precompute()
			keyBlob := encodeRSAPublicKeyBlob(&k.PublicKey)
			return &LoadedSshKey{
				RSAKey:    k,
				PublicKey: ParsePublicKeyBlob(keyBlob, "rsa-pkcs8-key"),
			}, nil
		case ed25519.PrivateKey:
			pub := k.Public().(ed25519.PublicKey)
			var keyBlob []byte
			keyBlob = writeSSHString(keyBlob, "ssh-ed25519")
			keyBlob = writeSSHBytes(keyBlob, pub)
			return &LoadedSshKey{
				SigningKey: k,
				PublicKey:  ParsePublicKeyBlob(keyBlob, "ed25519-pkcs8-key"),
			}, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", parsed)
		}

	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

func decryptLegacyPEMBlock(block *pem.Block, passphrase string) ([]byte, error) {
	dekInfo := block.Headers["DEK-Info"]
	parts := strings.Split(dekInfo, ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info header %q", dekInfo)
	}
	alg := strings.ToUpper(strings.TrimSpace(parts[0]))
	iv, err := hex.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid DEK-Info IV hex: %w", err)
	}
	var keyLen int
	switch alg {
	case "AES-128-CBC":
		keyLen = 16
	case "AES-192-CBC":
		keyLen = 24
	case "AES-256-CBC":
		keyLen = 32
	default:
		return nil, fmt.Errorf("unsupported encrypted PEM cipher %q (supported: AES-128/192/256-CBC or OPENSSH PRIVATE KEY)", alg)
	}
	if len(iv) != aes.BlockSize || len(block.Bytes)%aes.BlockSize != 0 {
		return nil, errors.New("invalid AES-CBC IV or ciphertext length in encrypted PEM")
	}

	// OpenSSL EVP_BytesToKey with MD5 and 8-byte salt (iv[:8])
	salt := iv[:8]
	var key []byte
	var prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(passphrase))
		h.Write(salt)
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	c, err := aes.NewCipher(key[:keyLen])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(block.Bytes))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(out, block.Bytes)
	if len(out) == 0 {
		return nil, ErrInvalidPassphrase
	}
	padLen := int(out[len(out)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(out) {
		return nil, ErrInvalidPassphrase
	}
	for i := len(out) - padLen; i < len(out); i++ {
		if int(out[i]) != padLen {
			return nil, ErrInvalidPassphrase
		}
	}
	return out[:len(out)-padLen], nil
}

func (k *LoadedSshKey) SignSSHData(data []byte, flags uint32) ([]byte, error) {
	if k.RSAKey != nil {
		var sigAlgo string
		var hashFunc crypto.Hash
		var digest []byte

		if (flags & sshAgentRSASHA2_512) != 0 {
			sigAlgo = "rsa-sha2-512"
			hashFunc = crypto.SHA512
			sum := sha512.Sum512(data)
			digest = sum[:]
		} else if (flags & sshAgentRSASHA2_256) != 0 {
			sigAlgo = "rsa-sha2-256"
			hashFunc = crypto.SHA256
			sum := sha256.Sum256(data)
			digest = sum[:]
		} else {
			parsedCtx := ParseSshAuthContext(data)
			switch parsedCtx.GetPubkeyAlgorithm() {
			case "rsa-sha2-512":
				sigAlgo = "rsa-sha2-512"
				hashFunc = crypto.SHA512
				sum := sha512.Sum512(data)
				digest = sum[:]
			case "rsa-sha2-256":
				sigAlgo = "rsa-sha2-256"
				hashFunc = crypto.SHA256
				sum := sha256.Sum256(data)
				digest = sum[:]
			default:
				sigAlgo = "ssh-rsa"
				hashFunc = crypto.SHA1
				sum := sha1.Sum(data)
				digest = sum[:]
			}
		}

		sig, err := rsa.SignPKCS1v15(nil, k.RSAKey, hashFunc, digest)
		if err != nil {
			return nil, err
		}
		var out []byte
		out = writeSSHString(out, sigAlgo)
		out = writeSSHBytes(out, sig)
		return out, nil
	}

	sig := ed25519.Sign(k.SigningKey, data)
	var out []byte
	out = writeSSHString(out, "ssh-ed25519")
	out = writeSSHBytes(out, sig)
	return out, nil
}

func decryptOpenSSHPrivateSection(ciphername, kdfname string, kdfoptions []byte, passphrase string, ciphertext []byte) ([]byte, error) {
	if kdfname != "bcrypt" {
		return nil, fmt.Errorf("unsupported OpenSSH KDF %q", kdfname)
	}
	optCursor := kdfoptions
	salt, ok1 := readBytes(&optCursor)
	rounds, ok2 := readU32(&optCursor)
	if !ok1 || !ok2 {
		return nil, errors.New("invalid bcrypt kdfoptions")
	}

	switch ciphername {
	case "aes256-ctr":
		if len(ciphertext)%16 != 0 {
			return nil, errors.New("aes256-ctr ciphertext length is not a multiple of 16")
		}
		keyAndIV, err := bcryptPBKDF([]byte(passphrase), salt, rounds, 48)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(keyAndIV[:32])
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(ciphertext))
		stream := cipher.NewCTR(block, keyAndIV[32:48])
		stream.XORKeyStream(out, ciphertext)
		return out, nil
	case "chacha20-poly1305@openssh.com":
		if len(ciphertext) < 8 || len(ciphertext)%8 != 0 {
			return nil, errors.New("chacha20-poly1305@openssh.com ciphertext length invalid")
		}
		keyMaterial, err := bcryptPBKDF([]byte(passphrase), salt, rounds, 64)
		if err != nil {
			return nil, err
		}
		var mainKey [32]byte
		copy(mainKey[:], keyMaterial[:32])
		var nonce [8]byte
		return chacha20XOR(mainKey, nonce, 1, ciphertext), nil
	default:
		return nil, fmt.Errorf("unsupported OpenSSH cipher %q", ciphername)
	}
}

func chacha20QuarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

func chacha20XOR(key [32]byte, nonce [8]byte, initialCounter uint64, input []byte) []byte {
	out := make([]byte, len(input))
	copy(out, input)
	counter := initialCounter
	for offset := 0; offset < len(out); offset += 64 {
		state := [16]uint32{
			0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
			binary.LittleEndian.Uint32(key[0:4]),
			binary.LittleEndian.Uint32(key[4:8]),
			binary.LittleEndian.Uint32(key[8:12]),
			binary.LittleEndian.Uint32(key[12:16]),
			binary.LittleEndian.Uint32(key[16:20]),
			binary.LittleEndian.Uint32(key[20:24]),
			binary.LittleEndian.Uint32(key[24:28]),
			binary.LittleEndian.Uint32(key[28:32]),
			uint32(counter),
			uint32(counter >> 32),
			binary.LittleEndian.Uint32(nonce[0:4]),
			binary.LittleEndian.Uint32(nonce[4:8]),
		}
		working := state
		for i := 0; i < 10; i++ {
			chacha20QuarterRound(&working, 0, 4, 8, 12)
			chacha20QuarterRound(&working, 1, 5, 9, 13)
			chacha20QuarterRound(&working, 2, 6, 10, 14)
			chacha20QuarterRound(&working, 3, 7, 11, 15)
			chacha20QuarterRound(&working, 0, 5, 10, 15)
			chacha20QuarterRound(&working, 1, 6, 11, 12)
			chacha20QuarterRound(&working, 2, 7, 8, 13)
			chacha20QuarterRound(&working, 3, 4, 9, 14)
		}
		var ks [64]byte
		for i := 0; i < 16; i++ {
			binary.LittleEndian.PutUint32(ks[i*4:(i+1)*4], working[i]+state[i])
		}
		end := offset + 64
		if end > len(out) {
			end = len(out)
		}
		for i := offset; i < end; i++ {
			out[i] ^= ks[i-offset]
		}
		counter++
	}
	return out
}
