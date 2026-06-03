package crypto

import (
	"crypto/sha256"
	"fmt"
)

// RotateKeyMaterial derives a new set of keys from the current TrafficEncKey.
// It uses HKDF-SHA256 with info="meridian-renewal-<generation>".
func RotateKeyMaterial(current *KeyMaterial, generation uint32) (*KeyMaterial, error) {
	if current == nil {
		return nil, fmt.Errorf("crypto: current KeyMaterial is nil")
	}

	info := []byte(fmt.Sprintf("meridian-renewal-%d", generation))
	const totalLen = KeyLen*2 + NonceSeedLen*2 + KeyLen // 128 bytes
	
	kb := hkdfExpand(sha256.New, current.TrafficEncKey[:], nil, info, totalLen)
	
	keys := &KeyMaterial{}
	offset := 0
	copy(keys.TrafficEncKey[:], kb[offset:offset+KeyLen])
	offset += KeyLen
	copy(keys.TrafficMACKey[:], kb[offset:offset+KeyLen])
	offset += KeyLen
	copy(keys.NonceSeedUplink[:], kb[offset:offset+NonceSeedLen])
	offset += NonceSeedLen
	copy(keys.NonceSeedDownlk[:], kb[offset:offset+NonceSeedLen])
	offset += NonceSeedLen
	copy(keys.InitKey[:], kb[offset:offset+KeyLen])
	
	return keys, nil
}
