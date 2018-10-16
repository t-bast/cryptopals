package padding

// PKCS7 adds padding to the given message according to the PKCS#7 spec.
func PKCS7(message []byte, blockLen int) []byte {
	paddedMsgLen := len(message)
	if len(message)%blockLen == 0 {
		paddedMsgLen += blockLen
	} else {
		paddedMsgLen = paddedMsgLen + blockLen - (len(message) % blockLen)
	}

	paddedMsg := make([]byte, paddedMsgLen)
	copy(paddedMsg, message)

	paddingLen := paddedMsgLen - len(message)
	for i := len(message); i < paddedMsgLen; i++ {
		paddedMsg[i] = byte(paddingLen)
	}

	return paddedMsg
}

// UnPKCS7 removes padding from the given message according to the PKCS#7 spec.
func UnPKCS7(paddedMsg []byte, blockLen int) []byte {
	paddingLen := paddedMsg[len(paddedMsg)-1]
	for i := 1; i <= int(paddingLen); i++ {
		if paddedMsg[len(paddedMsg)-i] != paddingLen {
			panic(map[string]string{
				"msg": string(paddedMsg),
				"err": "invalid PKCS#7 padding",
			})
		}
	}

	return paddedMsg[:len(paddedMsg)-int(paddingLen)]
}
