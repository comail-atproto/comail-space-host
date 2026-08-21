package spacecredential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

const dpopProofType = "dpop+jwt"

type publicJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

type dpopHeader struct {
	Algorithm string    `json:"alg"`
	Type      string    `json:"typ"`
	JWK       publicJWK `json:"jwk"`
}

type dpopClaims struct {
	JWTID      string `json:"jti"`
	HTTPMethod string `json:"htm"`
	TargetURI  string `json:"htu"`
	TokenHash  string `json:"ath,omitempty"`
	IssuedAt   int64  `json:"iat"`
}

func newDPoPProof(key atcrypto.PrivateKey, method, rawURL string, credential *string, now time.Time) (string, error) {
	if method == "" || method != strings.ToUpper(method) {
		return "", errors.New("spacecredential: DPoP method must be exact uppercase")
	}
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme == "" || target.Host == "" || target.User != nil {
		return "", errors.New("spacecredential: DPoP target must be an absolute clean URL")
	}
	public, err := key.PublicKey()
	if err != nil {
		return "", errors.New("spacecredential: derive DPoP public key")
	}
	jwk, err := p256PublicJWK(public)
	if err != nil {
		return "", err
	}
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", errors.New("spacecredential: generate DPoP identifier")
	}
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	target.RawFragment = ""
	canonicalizeTargetOrigin(target)
	claims := dpopClaims{
		JWTID: hex.EncodeToString(jtiBytes), HTTPMethod: method,
		TargetURI: target.Scheme + "://" + target.Host + target.EscapedPath(),
		IssuedAt:  now.UTC().Unix(),
	}
	if claims.TargetURI == target.Scheme+"://"+target.Host {
		claims.TargetURI += "/"
	}
	if credential != nil {
		hash := sha256.Sum256([]byte(*credential))
		claims.TokenHash = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	header := dpopHeader{Algorithm: "ES256", Type: dpopProofType, JWK: jwk}
	return signCompactJWT(key, header, claims)
}

func canonicalizeTargetOrigin(target *url.URL) {
	target.Scheme = strings.ToLower(target.Scheme)
	hostname := strings.ToLower(target.Hostname())
	port := target.Port()
	if (target.Scheme == "https" && port == "443") || (target.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		target.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		target.Host = "[" + hostname + "]"
	} else {
		target.Host = hostname
	}
}

func p256PublicJWK(key atcrypto.PublicKey) (publicJWK, error) {
	if _, ok := key.(*atcrypto.PublicKeyP256); !ok {
		return publicJWK{}, errors.New("spacecredential: DPoP key must be P-256")
	}
	raw := key.UncompressedBytes()
	if len(raw) != 65 || raw[0] != 0x04 {
		return publicJWK{}, errors.New("spacecredential: invalid P-256 public key encoding")
	}
	return publicJWK{
		KeyType: "EC", Curve: "P-256",
		X: base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

func jwkThumbprint(jwk publicJWK) (string, error) {
	if jwk.KeyType != "EC" || jwk.Curve != "P-256" {
		return "", errors.New("spacecredential: thumbprint requires P-256 JWK")
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(x) != 32 {
		return "", errors.New("spacecredential: invalid P-256 JWK x coordinate")
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(y) != 32 {
		return "", errors.New("spacecredential: invalid P-256 JWK y coordinate")
	}
	if _, err := atcrypto.ParsePublicJWK(atcrypto.JWK{KeyType: "EC", Curve: "P-256", X: jwk.X, Y: jwk.Y}); err != nil {
		return "", errors.New("spacecredential: invalid P-256 JWK point")
	}
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	hash := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func signCompactJWT(key atcrypto.PrivateKey, header, claims any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", errors.New("spacecredential: encode JWT header")
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("spacecredential: encode JWT claims")
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	signature, err := key.HashAndSign([]byte(signingInput))
	if err != nil {
		return "", errors.New("spacecredential: sign JWT")
	}
	if len(signature) != 64 {
		return "", errors.New("spacecredential: invalid JWT signature length")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
