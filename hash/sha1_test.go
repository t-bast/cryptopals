package hash_test

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/hash"
)

func TestSha1Sum(t *testing.T) {
	m := []byte("YELLOW SUBMARINE")
	computed := hash.Sha1Sum(m)
	expected := sha1.Sum(m)
	assert.Equal(t, hex.EncodeToString(expected[:]), hex.EncodeToString(computed[:]))

	m = []byte("Rappelez-vous l'objet que nous vimes, mon ame," +
		"Ce beau matin d'ete si doux :" +
		"Au detour d'un sentier une charogne infame" +
		"Sur un lit seme de cailloux,")
	computed = hash.Sha1Sum(m)
	expected = sha1.Sum(m)
	assert.Equal(t, hex.EncodeToString(expected[:]), hex.EncodeToString(computed[:]))
}
