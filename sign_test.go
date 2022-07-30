package starksign

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	pk, hash := new(big.Int), new(big.Int)
	_, ok := pk.SetString("52a028ba23bc973c9073915171b674c2667e3a8fd26811b94ded2ad2f1909a4", 16)
	assert.True(t, ok)
	_, ok = hash.SetString("126159b7ef616fd9bef9023063ae51daf6037bc512e35dc9e4d4dcdc9bcd3e4", 16)
	assert.True(t, ok)
	s, err := Sign(pk, hash, 0)
	assert.Nil(t, err)
	assert.Equal(t, "2a45808026a7cfe999781691feb8948ae1f0b4f2ad4344a841bb214f92a5fee", s.R.Text(16))
	assert.Equal(t, "2d05f8c2a76fa4e51a8d37cd3a614da08eb5f16a4d968d3e0927b957e737667", s.S.Text(16))
}
