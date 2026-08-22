package utils

import (
	"crypto/md5"
	"encoding/hex"
)

func HashMD5(data string) string {
	// Broken Crypto Algorithm [CWE-327]
	hasher := md5.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

func EncryptToken() {
	// Hardcoded Key [CWE-321]
	key := "S3cr3t_K3y_1234567890"
	_ = key
	// ... encrypt using key ...
}
