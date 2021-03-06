package challenge

import (
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/block"
	"github.com/t-bast/cryptopals/cipher/padding"
	"github.com/t-bast/cryptopals/oracle"
	"github.com/t-bast/cryptopals/profile"
)

func TestSet2_Challenge1(t *testing.T) {
	padded := padding.PKCS7([]byte("YELLOW SUBMARINE"), 20)
	assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padded)
}

func TestSet2_Challenge2(t *testing.T) {
	testData := filepath.Join("testdata", "2_2.txt")
	encoded, err := ioutil.ReadFile(testData)
	require.NoError(t, err)
	require.Equal(t, 0, len(encoded)%16)

	encrypted, err := base64.StdEncoding.DecodeString(string(encoded))
	require.NoError(t, err)
	require.Equal(t, 0, len(encrypted)%16)

	iv := [16]byte{0}
	cbc := block.NewCBC([]byte("YELLOW SUBMARINE"), iv[:])
	decrypted := cbc.Decrypt(encrypted)
	expected := "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n"
	assert.Equal(t, expected, string(decrypted))
}

func TestSet2_Challenge3(t *testing.T) {
	o := oracle.NewEncryptionOracle()
	detectedMode := oracle.DetectEncryptionMode(o)
	assert.Equal(t, o.Mode, detectedMode)
}

func TestSet2_Challenge4(t *testing.T) {
	o := oracle.NewECBOracle()
	detectedSecret := oracle.DetectECBSecret(o)
	expected := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	assert.Equal(t, expected, string(detectedSecret[:len(expected)]))
}

func TestSet2_Challenge5(t *testing.T) {
	o := profile.NewUserProfileOracle()
	p := profile.CreateAdminProfile(o)
	assert.Equal(t, "admin", p.Role)
}

func TestSet2_Challenge6(t *testing.T) {
	o := oracle.NewECBOracle2()
	detectedSecret := oracle.DetectECBSecret2(o)
	expected := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	assert.Equal(t, expected, string(detectedSecret[:len(expected)]))
}

func TestSet2_Challenge8(t *testing.T) {
	o := oracle.NewCBCOracle()

	// Instead of ; and = that are going to be replaced by the encrypt method,
	// we use the ascii char just below them.
	// We make sure a padding of 1 is used so that our bit-flipping doesn't
	// produce an invalid padding.
	encrypted := o.Encrypt("\x3aadmin\x3ctrue\x3aAAAAAAAAA")

	// Then we do some bit-flipping on the ciphertext which will propagate to
	// next blocks and insert ; and = where we want them.
	encrypted[16] ^= 1
	encrypted[22] ^= 1
	encrypted[27] ^= 1

	assert.True(t, o.CheckAdmin(encrypted))
}
