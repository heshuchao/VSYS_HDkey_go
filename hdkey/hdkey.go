package hdkey

func GenerateParentPublicKey(seed []byte, path string) (string, error) {
	publicKey, err := derivedPublicKeyWithAbsolutePath(seed, path)
	if err != nil {
		return "", err
	}
	return publicKey.encodeToString(), nil
}

func GenerateChildPublicKeyBytes(parentKeyStr string, serialize uint32) ([]byte, error) {
	parentKey, err := decodeFromString(parentKeyStr)
	if err != nil {
		return nil, err
	}
	childKey, err := parentKey.genPublicChild(serialize)
	if err != nil {
		return nil, err
	}

	return childKey.getVSYSPublicPoint()
}

func GeneratePrivateKeyBytes(seed []byte, path string) ([]byte, error) {
	priKey, err := derivedPrivateKeyWithAbsolutePath(seed, path)
	if err != nil {
		return nil, err
	}
	return priKey.key, nil
}
