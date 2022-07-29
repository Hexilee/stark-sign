/*
Package rfc6979 is an implementation of RFC 6979's deterministic DSA.
	Such signatures are compatible with standard Digital Signature Algorithm
	(DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA) digital
	signatures and can be processed with unmodified verifiers, which need not be
	aware of the procedure described therein.  Deterministic signatures retain
	the cryptographic security features associated with digital signatures but
	can be more easily implemented in various environments, since they do not
	need access to a source of high-quality randomness.
(https://tools.ietf.org/html/rfc6979)
Provides functions similar to crypto/dsa and crypto/ecdsa.

Fork from https://github.com/codahale/rfc6979
*/
package starksign

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math/big"
)

// mac returns an HMAC of the given key and message.
func mac(alg func() hash.Hash, k, m, buf []byte) []byte {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(buf[:0])
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	vlen := len(in) * 8
	v := new(big.Int).SetBytes(in)
	if vlen > qlen {
		v = new(big.Int).Rsh(v, uint(vlen-qlen))
	}
	return v
}

// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(v *big.Int, rolen int) []byte {
	out := v.Bytes()

	// pad with zeros if it's too short
	if len(out) < rolen {
		out2 := make([]byte, rolen)
		copy(out2[rolen-len(out):], out)
		return out2
	}

	// drop most significant bytes if it's too long
	if len(out) > rolen {
		out2 := make([]byte, rolen)
		copy(out2, out[len(out)-rolen:])
		return out2
	}

	return out
}

// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(in []byte, q *big.Int, qlen, rolen int) []byte {
	z1 := bits2int(in, qlen)
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		return int2octets(z1, rolen)
	}
	return int2octets(z2, rolen)
}

var one = big.NewInt(1)

// https://tools.ietf.org/html/rfc6979#section-3.2
// Generate the ``k`` value - the nonce for DSA.
// - order: order of the DSA generator used in the signature
// - privateKey: secure exponent in numeric form
// - hashFunc: reference to the same hash function used for generating hash, like hashlib.sha1
// - hash: hash in binary form of the signing data
// - extraEntropy: additional added data in binary form as per section-3.6 of rfc6979
func generateK(order, privateKey *big.Int, hashFunc func() hash.Hash, hash, extraEntropy []byte) *big.Int {
	qlen := order.BitLen()
	holen := hashFunc().Size()
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(privateKey, rolen), bits2octets(hash, order, qlen, rolen)...)
	bx = append(bx, extraEntropy...)

	// Step B
	v := bytes.Repeat([]byte{0x01}, holen)

	// Step C
	k := bytes.Repeat([]byte{0x00}, holen)

	// Step D
	k = mac(hashFunc, k, append(append(v, 0x00), bx...), k)

	// Step E
	v = mac(hashFunc, k, v, v)

	// Step F
	k = mac(hashFunc, k, append(append(v, 0x01), bx...), k)

	// Step G
	v = mac(hashFunc, k, v, v)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t) < qlen/8 {
			v = mac(hashFunc, k, v, v)
			t = append(t, v...)
		}

		// Step H3
		secret := bits2int(t, qlen)
		if secret.Cmp(one) >= 0 && secret.Cmp(order) < 0 {
			return secret
		}
		k = mac(hashFunc, k, append(v, 0x00), k)
		v = mac(hashFunc, k, v, v)
	}
}
