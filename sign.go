package starksign

import (
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

	ECPoint struct {
		X, Y *big.Int
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
	if qlen%8 >= 1 && qlen%8 <= 4 && qlen >= 248 {
		hash = new(big.Int).Mul(hash, big.NewInt(16))
	}

	var extraEntropy = make([]byte, 0)
	if seed != 0 {
		extraEntropy = int2octets(big.NewInt(seed), qlen)
	}
	return generateK(EC_ORDER, privateKey, sha256.New, int2octets(hash, rolen), extraEntropy)
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

	ecBase := &ECPoint{
		X: GX,
		Y: GY,
	}

	for {
		k := generateKWithSeed(hash, privateKey, seed)
		//  Update seed for next iteration in case the value of k is bad.

		seed++

		p, err := ecMult(ecBase, k, big.NewInt(ALPHA), FIELD_PRIME)
		if err != nil {
			return nil, err
		}
		// DIFF: in classic ECDSA, we take x % n.
		r := p.X

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

// Multiplies by m a point on the elliptic curve with equation y^2 = x^3 + alpha*x + beta mod p.
// Assumes the point is given in affine form (x, y) and that 0 < m < order(point).
func ecMult(point *ECPoint, m, alpha, p *big.Int) (*ECPoint, error) {
	if m.Cmp(big.NewInt(1)) == 0 {
		return point, nil
	}

	if new(big.Int).Mod(m, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		doubleP, err := ecDouble(point, alpha, p)
		if err != nil {
			return nil, err
		}
		return ecMult(doubleP, new(big.Int).Div(m, big.NewInt(2)), alpha, p)
	}

	multP, err := ecMult(point, new(big.Int).Sub(m, big.NewInt(1)), alpha, p)
	if err != nil {
		return nil, err
	}
	return ecAdd(multP, point, p)
}

// Gets two points on an elliptic curve mod p and returns their sum.
// Assumes the points are given in affine form (x, y) and have different x coordinates.
func ecAdd(point1, point2 *ECPoint, p *big.Int) (*ECPoint, error) {
	// (x1 - x2) % p == 0
	if new(big.Int).Mod(new(big.Int).Sub(point1.X, point2.X), p).Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("invalid points")
	}

	// m = (y1 - y2) / (x1 - x2) % p
	m := divMod(new(big.Int).Sub(point1.Y, point2.Y), new(big.Int).Sub(point1.X, point2.X), p)

	// x = m^2 - x1 - x2
	x := new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(m, m), point1.X), point2.X)

	// y = m * (x1 - x) - y1
	y := new(big.Int).Sub(new(big.Int).Mul(m, new(big.Int).Sub(point1.X, x)), point1.Y)

	return &ECPoint{X: new(big.Int).Mod(x, p), Y: new(big.Int).Mod(y, p)}, nil
}

// Doubles a point on an elliptic curve with the equation y^2 = x^3 + alpha*x + beta mod p.
// Assumes the point is given in affine form (x, y) and has y != 0.
func ecDouble(point *ECPoint, alpha *big.Int, p *big.Int) (*ECPoint, error) {
	if new(big.Int).Mod(point.X, p).Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("invalid point")
	}

	// m = (3 * x1**2 + alpha) / (2 * y1) % p
	m := divMod(new(big.Int).Add(new(big.Int).Mul(new(big.Int).Mul(point.X, point.X), big.NewInt(3)), alpha), new(big.Int).Mul(big.NewInt(2), point.Y), p)

	// x = (m**2 - 2 * x1) % p
	x := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(m, m), new(big.Int).Mul(big.NewInt(2), point.X)), p)

	// y = (m * (x1 - x) - y1) % p
	y := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(m, new(big.Int).Sub(point.X, x)), point.Y), p)

	return &ECPoint{X: x, Y: y}, nil
}

// Finds a nonnegative integer 0 <= x < p such that (m * x) % p == n
func divMod(m, n, p *big.Int) *big.Int {
	return big.NewInt(0).Mod(big.NewInt(0).Mul(m, big.NewInt(0).ModInverse(n, p)), p)
}
