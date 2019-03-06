package hdkey

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/VSYS_HDkey_go/curvepoints"
)

const (
	HardenedKeyStart uint32 = 0x70000000
	maxUint8                = 1<<8 - 1
)

var (
	vsysPubPrefix = []byte{0x55, 0x3f, 0x8b, 0xe7, 0x68, 0x93, 0x66}
	vsysPrvPrefix = []byte{0x55, 0x3f, 0x8b, 0xe7, 0x4c, 0xe8, 0x33}
)

type ExtendedKey struct {
	depth      uint8
	parentFP   []byte
	serializes uint32
	chainCode  []byte
	key        []byte
	isPrivate  bool
}

func newExtendedKey(key, chainCode, parentFP []byte, depth uint8, serializes uint32, isPrivate bool) *ExtendedKey {

	return &ExtendedKey{
		depth:      depth,
		parentFP:   parentFP,
		serializes: serializes,
		chainCode:  chainCode,
		key:        key,
		isPrivate:  isPrivate,
	}
}

func getI(data, key []byte, serializes uint32) []byte {
	tmp := [4]byte{}
	hmac512 := hmac.New(sha512.New, key)
	binary.BigEndian.PutUint32(tmp[:], serializes)
	hmac512.Write(data)
	hmac512.Write(tmp[:])
	return hmac512.Sum(nil)
}

func getFP(key []byte, isPrivate bool) []byte {
	fingerPrint := []byte{}
	sha256ctx := sha256.New()
	if !isPrivate {
		sha256ctx.Write(key)
	} else {
		pubkey := curvepoints.GeneratePublicKeyEd(arrayToFixedLength(key))
		sha256ctx.Write(pubkey[:])
	}
	fingerPrint = sha256ctx.Sum(nil)[:4]
	return fingerPrint
}

func inverse(data []byte) []byte {
	ret := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		ret[i] = data[len(data)-1-i]
	}
	return ret
}

func arrayToFixedLength(in []byte) (out [32]byte) {
	copy(out[:], in[:32])
	return out
}

func getPriChildViaPriParent(il, prikey []byte) []byte {
	priChild := []byte{}

	ilNum := new(big.Int).SetBytes(inverse(il[:28]))
	kpr := new(big.Int).SetBytes(inverse(prikey))
	num8 := new(big.Int).SetBytes([]byte{8})
	ilNum.Mul(ilNum, num8)
	ilNum.Add(ilNum, kpr)

	priChild = ilNum.Bytes()
	if len(priChild) < 32 {
		for i := 0; i < 32-len(priChild); i++ {
			priChild = append([]byte{0x00}, priChild...)
		}
	}
	priChild = inverse(priChild)

	return priChild
}

func getPubChildViaPubParent(il, pubkey []byte) ([]byte, error) {

	ilNum := new(big.Int).SetBytes(inverse(il[:28]))
	num8 := new(big.Int).SetBytes([]byte{8})
	ilNum.Mul(ilNum, num8)

	il2 := ilNum.Bytes()
	il2Len := len(il2)
	if il2Len < 32 {
		for i := 0; i < 32-il2Len; i++ {
			il2 = append([]byte{0x00}, il2...)
		}
	}
	il2 = inverse(il2)
	point := [32]byte{}
	fixedPub := arrayToFixedLength(pubkey)
	fixedIl2 := arrayToFixedLength(il2)

	if curvepoints.ScalarMultBaseAdd(&fixedPub, &fixedIl2, &point) == false {
		return nil, errors.New("Infinity point!")
	}

	return point[:], nil

}

func (k *ExtendedKey) genPrivateChild(serializes uint32) (*ExtendedKey, error) {
	i := []byte{}
	childChainCode := []byte{}

	if k.depth == maxUint8 {
		return nil, errors.New("Cannot derived a key with more than 255 indices in its path")
	}

	if !k.isPrivate {
		return nil, errors.New("Unable to create private keys from a public extended key!")
	}

	if serializes >= HardenedKeyStart {
		i = getI(k.key, k.chainCode, serializes)
	} else {
		point := curvepoints.GeneratePublicKeyEd(arrayToFixedLength(k.key))
		i = getI(point[:], k.chainCode, serializes)
	}

	childKey := getPriChildViaPriParent(i[:32], k.key)

	childChainCode = i[32:]

	parentFP := getFP(k.key, k.isPrivate)
	return newExtendedKey(childKey, childChainCode, parentFP, k.depth+1, serializes, true), nil
}

func (k *ExtendedKey) genPublicChild(serializes uint32) (*ExtendedKey, error) {
	if !k.isPrivate {
		if serializes >= HardenedKeyStart {
			return nil, errors.New("Cannot derive a hardened key from a public key!")
		}
		i := getI(k.key, k.chainCode, serializes)
		childKey, err := getPubChildViaPubParent(i[:32], k.key)
		if err != nil {
			return nil, err
		}
		childChainCode := i[len(i)/2:]

		parentFP := getFP(k.key, false)
		return newExtendedKey(childKey, childChainCode, parentFP, k.depth+1, serializes, false), nil

	}
	childPrikey, err := k.genPrivateChild(serializes)

	if err != nil {
		return nil, err
	}
	childKey := curvepoints.GeneratePublicKeyEd(arrayToFixedLength(childPrikey.key))
	return newExtendedKey(childKey[:], childPrikey.chainCode, childPrikey.parentFP, k.depth+1, serializes, false), nil

}

func initRootKeyFromSeed(seed []byte) (*ExtendedKey, error) {

	ctx := sha512.New()
	ctx.Write(seed)
	i := ctx.Sum(nil)

	i[0] &= 248
	i[31] &= 127
	i[31] |= 64

	rootParentFP := [4]byte{0, 0, 0, 0}
	return newExtendedKey(i[:32], i[32:], rootParentFP[:], 0, 0, true), nil
}
func derivedPrivateKeyWithAbsolutePath(seed []byte, derivedPath string) (*ExtendedKey, error) {

	path := strings.Replace(derivedPath, " ", "", -1)

	if path == "m" || path == "/" || path == "" {
		return initRootKeyFromSeed(seed)
	}

	if strings.Index(path, "m/") != 0 {
		return nil, errors.New("Invalid derived path!")
	}

	priKey, err := initRootKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	path = path[2:]
	elements := strings.Split(path, "/")

	for _, elem := range elements {
		var hdSerializes uint32
		if len(elem) == 0 {
			return nil, errors.New("Invalid derived path!")
		}

		if strings.Index(elem, "'") == len(elem)-1 {
			elem = elem[0 : len(elem)-1]
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, errors.New("Invalid derived path!")
			}
			hdSerializes = uint32(index) + HardenedKeyStart
		} else {
			index, err := strconv.Atoi(elem)
			if err != nil {
				return nil, errors.New("Invalid derived path!")
			}
			hdSerializes = uint32(index)
		}

		priKey, err = priKey.genPrivateChild(hdSerializes)
		if err != nil {
			return nil, err
		}

	}
	return priKey, nil
}

func (k *ExtendedKey) getPublicExtendedStruct() (*ExtendedKey, error) {
	if !k.isPrivate {
		return k, nil
	}
	pubkey := curvepoints.GeneratePublicKeyEd(arrayToFixedLength(k.key))

	return newExtendedKey(pubkey[:], k.chainCode, k.parentFP, k.depth, k.serializes, false), nil
}

func derivedPublicKeyWithAbsolutePath(seed []byte, derivedPath string) (*ExtendedKey, error) {
	privateKey, err := derivedPrivateKeyWithAbsolutePath(seed, derivedPath)
	if err != nil {
		return nil, err
	}
	return privateKey.getPublicExtendedStruct()
}

func (k *ExtendedKey) encodeToString() string {
	byteStruct := make([]byte, 0)
	if k.isPrivate {
		byteStruct = append(byteStruct, vsysPrvPrefix...)
	} else {
		byteStruct = append(byteStruct, vsysPubPrefix...)
	}
	byteStruct = append(byteStruct, k.depth)
	byteStruct = append(byteStruct, k.parentFP...)
	serBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(serBytes[:], k.serializes)
	byteStruct = append(byteStruct, serBytes...)
	byteStruct = append(byteStruct, k.chainCode...)
	byteStruct = append(byteStruct, k.key...)
	return Encode(byteStruct, BitcoinAlphabet)
}

func decodeFromString(data string) (*ExtendedKey, error) {
	byteStruct, err := Decode(data, BitcoinAlphabet)
	if err != nil || len(byteStruct) != 80 {
		return nil, err
	}
	var ret ExtendedKey
	isPrivate := false
	if reflect.DeepEqual(vsysPrvPrefix, byteStruct[:7]) {
		isPrivate = true
	} else if reflect.DeepEqual(vsysPubPrefix, byteStruct[:7]) {
		isPrivate = false
	} else {
		return nil, errors.New("Invalid base58 data!")
	}
	ret.isPrivate = isPrivate
	ret.depth = byteStruct[7]
	ret.parentFP = byteStruct[8:12]
	serializes := binary.BigEndian.Uint32(byteStruct[12:16])
	ret.serializes = serializes
	ret.chainCode = byteStruct[16:48]
	ret.key = byteStruct[48:80]

	return &ret, nil
}

func (k *ExtendedKey) getVSYSPublicPoint() ([]byte, error) {
	vsysPub, err := curvepoints.ConvertEdToX(arrayToFixedLength(k.key))
	if err != nil {
		return nil, err
	}
	return vsysPub[:], nil
}
