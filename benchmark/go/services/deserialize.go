package services

import (
	"bytes"
	"encoding/gob"
)

func DeserializeData(data []byte) {
	// Insecure Deserialization [CWE-502]
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	
	var result map[string]interface{}
	dec.Decode(&result)
}
