package challenge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/oracle"
)

func TestSet3_Challenge1(t *testing.T) {
	assert.NoError(t, oracle.DecryptWithPaddingOracle(oracle.NewPaddingOracle()))
}
