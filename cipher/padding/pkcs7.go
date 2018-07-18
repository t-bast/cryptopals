package padding

// PKCS7 adds padding to the given block according to the PKCS#7 spec.
func PKCS7(lastBlock []byte, blockLen int) []byte {
	padded := make([]byte, blockLen)
	copy(padded, lastBlock)

	paddingLen := blockLen - len(lastBlock)
	for i := len(lastBlock); i < blockLen; i++ {
		padded[i] = byte(paddingLen)
	}

	return padded
}
