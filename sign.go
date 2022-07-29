package starksign

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func init() {
	if err := EC_ORDER.UnmarshalText([]byte("3618502788666131213697322783095070105526743751716087489154079457884512865583")); err != nil {
		panic(fmt.Errorf("Failed to parse EC_ORDER: %v", err))
	}
	if err := BETA.UnmarshalText([]byte("3141592653589793238462643383279502884197169399375105820974944592307816406665")); err != nil {
		panic(fmt.Errorf("Failed to parse BETA: %v", err))
	}
	if err := FIELD_PRIME.UnmarshalText([]byte("3618502788666131213697322783095070105623107215331596699973092056135872020481")); err != nil {
		panic(fmt.Errorf("Failed to parse FIELD_PRIME: %v", err))
	}
	if err := GX.UnmarshalText([]byte("874739451078007766457464989774322083649278607533249481151382481072868806602")); err != nil {
		panic(fmt.Errorf("Failed to parse GX: %v", err))
	}
	if err := GY.UnmarshalText([]byte("152666792071518830868575557812948353041420400780739481342941381225525861407")); err != nil {
		panic(fmt.Errorf("Failed to parse GY: %v", err))
	}
}

var (
	EC_ORDER    = new(big.Int)
	BETA        = new(big.Int)
	FIELD_PRIME = new(big.Int)

	GX = new(big.Int)
	GY = new(big.Int)
)

type (
	ECSignature struct {
		R, S *big.Int
	}
)

const (
	N_ELEMENT_BITS_ECDSA = 251
	ALPHA                = 1
)

func generateKWithSeed(hash, privateKey *big.Int, seed int64) *big.Int {
	qlen := hash.BitLen()
	rolen := (qlen + 7) >> 3
	// Pad the message hash, for consistency with the elliptic.js library.
	if qlen >= 1 && qlen <= 4 && qlen >= 248 {
		hash = new(big.Int).Mul(hash, big.NewInt(16))
	}

	var extraEntropy = make([]byte, 0)
	if seed != 0 {
		extraEntropy = int2octets(big.NewInt(seed), qlen)
	}
	return generateK(EC_ORDER, hash, sha256.New, int2octets(privateKey, rolen), extraEntropy)
}

func Sign(hash, privateKey *big.Int, seed int64) (*ECSignature, error) {
	// check if lowBand <= target < 2 ** N_ELEMENT_BITS_ECDSA
	validBigInt := func(lowBand int64, target *big.Int) bool {
		return target.Cmp(big.NewInt(lowBand)) >= 0 && target.Cmp(big.NewInt(0).Exp(big.NewInt(2), big.NewInt(N_ELEMENT_BITS_ECDSA), big.NewInt(0))) < 0
	}

	// Note: hash must be smaller than 2**N_ELEMENT_BITS_ECDSA.
	// Message whose hash is >= 2**N_ELEMENT_BITS_ECDSA cannot be signed.
	// This happens with a very small probability.
	if !validBigInt(0, hash) {
		return nil, fmt.Errorf("hash is invalid")
	}

	curve := &elliptic.CurveParams{
		P:       FIELD_PRIME,
		B:       BETA,
		N:       EC_ORDER,
		Gx:      GX,
		Gy:      GY,
		BitSize: N_ELEMENT_BITS_ECDSA,
		Name:    "Stark Curve",
	}

	for {
		k := generateKWithSeed(hash, privateKey, seed)
		//  Update seed for next iteration in case the value of k is bad.
		seed++

		x, _ := curve.ScalarBaseMult(k.Bytes())
		// DIFF: in classic ECDSA, we take x % n.
		r := x
		if !validBigInt(1, r) {
			// Bad value. This fails with negligible probability.
			continue
		}

		// s = hash + r * privateKey
		s0 := big.NewInt(0).Add(hash, big.NewInt(0).Mul(r, privateKey))

		if big.NewInt(0).Mod(s0, EC_ORDER).Cmp(big.NewInt(0)) == 0 {
			// Bad value. This fails with negligible probability.
			continue
		}

		w := divMod(k, s0, EC_ORDER)
		if !validBigInt(1, w) {
			// Bad value. This fails with negligible probability.
			continue
		}
		s := big.NewInt(0).ModInverse(w, EC_ORDER)
		return &ECSignature{R: r, S: s}, nil
	}
}

// Finds a nonnegative integer 0 <= x < p such that (m * x) % p == n
func divMod(m, n, p *big.Int) *big.Int {
	return big.NewInt(0).Mod(big.NewInt(0).Mul(m, big.NewInt(0).ModInverse(n, p)), p)
}
