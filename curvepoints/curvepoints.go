package curvepoints

import (
	"errors"

	"github.com/VSYS_HDkey_go/edwards25519"
)

func cryptoVerify32(x, y [32]byte) uint32 {
	differentbits := uint32(0)
	for index := 0; index < 32; index++ {
		differentbits |= uint32(x[index] ^ y[index])
	}
	return differentbits
}

func feIsZero(f edwards25519.FieldElement) bool {
	zero := [32]byte{0}
	var s [32]byte

	edwards25519.FeToBytes(&s, &f)
	if cryptoVerify32(s, zero) != 0 {
		return false
	}
	return true
}

func feIsOne(f edwards25519.FieldElement) bool {
	one := [32]byte{0}
	var s [32]byte

	one[0] = 1
	edwards25519.FeToBytes(&s, &f)
	if cryptoVerify32(s, one) != 0 {
		return false
	}
	return true
}

func feIsReduced(s [32]byte) bool {
	var (
		strict [32]byte
		f      edwards25519.FieldElement
	)

	edwards25519.FeFromBytes(&f, &s)
	edwards25519.FeToBytes(&strict, &f)
	if cryptoVerify32(s, strict) != 0 {
		return true
	}
	return false
}

var d = edwards25519.FieldElement{-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116}
var sqrtm1 = edwards25519.FieldElement{-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482}

// func geFromBytesVarTime(s [32]byte) (edwards25519.ExtendedGroupElement, error) {
// 	var (
// 		h     edwards25519.ExtendedGroupElement
// 		u     edwards25519.FieldElement
// 		v     edwards25519.FieldElement
// 		v3    edwards25519.FieldElement
// 		vxx   edwards25519.FieldElement
// 		check edwards25519.FieldElement
// 	)

// 	edwards25519.FeFromBytes(&h.Y, &s)
// 	edwards25519.FeOne(&h.Z)
// 	edwards25519.FeSquare(&u, &h.Y)
// 	edwards25519.FeMul(&v, &u, &d)
// 	edwards25519.FeSub(&u, &u, &h.Z)
// 	edwards25519.FeAdd(&v, &v, &h.Z)

// 	edwards25519.FeSquare(&v3, &v)
// 	edwards25519.FeMul(&v3, &v3, &v)
// 	edwards25519.FeSquare(&h.X, &v3)
// 	edwards25519.FeMul(&h.X, &h.X, &v)
// 	edwards25519.FeMul(&h.X, &h.X, &u)

// 	edwards25519.FePow22523(&h.X, &h.X)
// 	edwards25519.FeMul(&h.X, &h.X, &v3)
// 	edwards25519.FeMul(&h.X, &h.X, &u)

// 	edwards25519.FeSquare(&vxx, &h.X)
// 	edwards25519.FeMul(&vxx, &vxx, &v)
// 	edwards25519.FeSub(&check, &vxx, &u)
// 	if edwards25519.FeIsNonZero(&check) != 0 {
// 		edwards25519.FeAdd(&check, &vxx, &u)
// 		if edwards25519.FeIsNonZero(&check) != 0 {
// 			return edwards25519.ExtendedGroupElement{}, errors.New("Failed to get extended group element from byte array!")
// 		}
// 		edwards25519.FeMul(&h.X, &h.X, &sqrtm1)
// 	}

// 	if edwards25519.FeIsNegative(&h.X) != ((s[31] >>7)&0x01){

// 	}

// 	return h, nil
// }

func montxToEdy(u edwards25519.FieldElement) edwards25519.FieldElement {
	var (
		one edwards25519.FieldElement
		um1 edwards25519.FieldElement
		up1 edwards25519.FieldElement
		y   edwards25519.FieldElement
	)

	edwards25519.FeOne(&one)
	edwards25519.FeSub(&um1, &one, &y)
	edwards25519.FeInvert(&um1, &um1)
	edwards25519.FeAdd(&up1, &y, &one)
	edwards25519.FeMul(&y, &um1, &up1)

	return y
}

func montFromEdy(y edwards25519.FieldElement) edwards25519.FieldElement {
	var (
		one edwards25519.FieldElement
		um1 edwards25519.FieldElement
		up1 edwards25519.FieldElement
		u   edwards25519.FieldElement
	)

	edwards25519.FeOne(&one)
	edwards25519.FeSub(&um1, &one, &y)
	edwards25519.FeInvert(&um1, &um1)
	edwards25519.FeAdd(&up1, &y, &one)
	edwards25519.FeMul(&u, &um1, &up1)

	return u
}

func GeneratePublicKeyEd(privateKey [32]byte) [32]byte {
	var A edwards25519.ExtendedGroupElement
	var pubkey [32]byte
	edwards25519.GeScalarMultBase(&A, &privateKey)
	A.ToBytes(&pubkey)
	return pubkey
}

func ConvertXToEd(x25519PubkeyBytes [32]byte) ([32]byte, error) {
	var (
		ed25519PubkeyBytes [32]byte
		u                  edwards25519.FieldElement
	)

	if feIsReduced(x25519PubkeyBytes) {
		return [32]byte{}, errors.New("The x25519 public key inputed is reduced!")
	}
	edwards25519.FeFromBytes(&u, &x25519PubkeyBytes)
	y := montxToEdy(u)
	edwards25519.FeToBytes(&ed25519PubkeyBytes, &y)
	return ed25519PubkeyBytes, nil
}

func ConvertEdToX(ed25519PubkeyBytes [32]byte) ([32]byte, error) {
	var (
		x25519PubkeyBytes [32]byte
		y                 edwards25519.FieldElement
	)

	edwards25519.FeFromBytes(&y, &ed25519PubkeyBytes)
	u := montFromEdy(y)
	edwards25519.FeToBytes(&x25519PubkeyBytes, &u)
	if feIsReduced(x25519PubkeyBytes) {
		return [32]byte{}, errors.New("The x25519 public key inputed is reduced!")
	}
	return x25519PubkeyBytes, nil
}

// point2 = point1 + [scalar] * B
// B for base point
// all in little endian
func ScalarMultBaseAdd(point1, scalar, point2 *[32]byte) bool {
	var (
		P1    edwards25519.ExtendedGroupElement   //p3
		R     edwards25519.ProjectiveGroupElement //p2
		recip edwards25519.FieldElement
		x     edwards25519.FieldElement
		y     edwards25519.FieldElement
		one   [32]byte
	)
	P1.FromBytes(point1)
	one[0] = 1
	edwards25519.GeDoubleScalarMultVartime(&R, &one, &P1, scalar)

	edwards25519.FeInvert(&recip, &R.Z)
	edwards25519.FeMul(&x, &R.X, &recip)
	edwards25519.FeMul(&y, &R.Y, &recip)

	if feIsZero(x) && feIsOne(y) {
		return false
	}
	edwards25519.FeToBytes(point2, &y)
	point2[31] ^= (edwards25519.FeIsNegative(&x) << 7)

	return true
}
