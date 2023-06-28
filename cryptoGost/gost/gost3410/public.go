// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package gost3410

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"gostx509/cryptoGost/x509/pkix"
	"math/big"
)

type PublicKey struct {
	C *Curve
	X *big.Int
	Y *big.Int
}

func NewPublicKey(curve *Curve, raw []byte) (*PublicKey, error) {
	pointSize := curve.PointSize()
	key := make([]byte, 2*pointSize)
	if len(raw) != len(key) {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", len(key))
	}
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	return &PublicKey{
		curve,
		bytes2big(key[pointSize : 2*pointSize]),
		bytes2big(key[:pointSize]),
	}, nil
}

func (pub *PublicKey) Raw() []byte {
	pointSize := pub.C.PointSize()
	raw := append(
		pad(pub.Y.Bytes(), pointSize),
		pad(pub.X.Bytes(), pointSize)...,
	)
	reverse(raw)
	return raw
}

func (pub *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	pointSize := pub.C.PointSize()
	if len(signature) != 2*pointSize {
		return false, fmt.Errorf("gogost/gost3410: len(signature) != %d", 2*pointSize)
	}
	s := bytes2big(signature[:pointSize])
	r := bytes2big(signature[pointSize:])
	if r.Cmp(zero) <= 0 ||
		r.Cmp(pub.C.Q) >= 0 ||
		s.Cmp(zero) <= 0 ||
		s.Cmp(pub.C.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pub.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	v := big.NewInt(0)
	v.ModInverse(e, pub.C.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pub.C.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pub.C.Q)
	z2.Sub(pub.C.Q, z2)
	p1x, p1y, err := pub.C.Exp(z1, pub.C.X, pub.C.Y)
	if err != nil {
		return false, err
	}
	q1x, q1y, err := pub.C.Exp(z2, pub.X, pub.Y)
	if err != nil {
		return false, err
	}
	lm := big.NewInt(0)
	lm.Sub(q1x, p1x)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.ModInverse(lm, pub.C.P)
	z1.Sub(q1y, p1y)
	lm.Mul(lm, z1)
	lm.Mod(lm, pub.C.P)
	lm.Mul(lm, lm)
	lm.Mod(lm, pub.C.P)
	lm.Sub(lm, p1x)
	lm.Sub(lm, q1x)
	lm.Mod(lm, pub.C.P)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.Mod(lm, pub.C.Q)
	return lm.Cmp(r) == 0, nil
}

func (our *PublicKey) Equal(theirKey crypto.PublicKey) bool {
	their, ok := theirKey.(*PublicKey)
	if !ok {
		return false
	}
	return our.X.Cmp(their.X) == 0 && our.Y.Cmp(their.Y) == 0 && our.C.Equal(their.C)
}

type PublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func GenKey(key *PublicKey, paramset, algorithm asn1.ObjectIdentifier) (PublicKeyInfo, error) {
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error
	publicKeyAlgorithm.Parameters.Bytes, err = GetParamBytesPK(paramset, algorithm)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	publicKeyAlgorithm.Parameters.FullBytes, err = GetFullBytesPK(publicKeyAlgorithm.Parameters.Bytes)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	raw, encodedPublicKey, err := GetRawPK(key, publicKeyAlgorithm)
	if err != nil {
		return PublicKeyInfo{}, err
	}
	publicKeyAlgorithm.Algorithm = Alg
	publicKeyAlgorithm.Parameters.Tag = 16
	publicKeyAlgorithm.Parameters.Class = 0
	publicKeyAlgorithm.Parameters.IsCompound = true

	return PublicKeyInfo{raw, publicKeyAlgorithm, *encodedPublicKey}, nil
}

func GetFullBytesPK(paramBytes []byte) ([]byte, error) {
	type A []byte

	ret, err := asn1.Marshal(A(paramBytes))
	if err != nil {
		return nil, err
	}
	ret[0] = 48

	return ret, nil
}

func GetParamBytesPK(paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	paramBytesPartOne, err := asn1.Marshal(paramset)
	if err != nil {
		return nil, err
	}

	paramBytesPartSecond, err := asn1.Marshal(algorithm)
	if err != nil {
		return nil, err
	}
	var paramBytes []byte
	paramBytes = append(paramBytes, paramBytesPartOne...)
	paramBytes = append(paramBytes, paramBytesPartSecond...)

	return paramBytes, nil
}

func GetRawPK(pub *PublicKey, publicKeyAlgorithm pkix.AlgorithmIdentifier) ([]byte, *asn1.BitString, error) {
	pkey, err := asn1.Marshal(pub.Raw())
	if err != nil {
		return nil, nil, err
	}

	var algWFB []byte = []byte{48, 0}
	resAlgWFB, err := asn1.Marshal(Alg)
	if err != nil {
		return nil, nil, err
	}

	resAlgWFB2, err := asn1.Marshal(publicKeyAlgorithm.Parameters.Bytes)
	if err != nil {
		return nil, nil, err
	}
	resAlgWFB2[0] = 48
	algWFB = append(algWFB, resAlgWFB...)
	algWFB = append(algWFB, resAlgWFB2...)
	algWFB[1] = byte(len(algWFB) - 2)

	var raw []byte = []byte{48, 0}
	raw = append(raw, algWFB...)
	encodedPublicKey := asn1.BitString{BitLength: len(pkey) * 8, Bytes: pkey}
	EPKB, err := asn1.Marshal(encodedPublicKey)
	if err != nil {
		return nil, nil, err
	}
	raw = append(raw, EPKB...)
	raw[1] = byte(len(raw) - 2)

	return raw, &encodedPublicKey, nil
}

type pkcs8Pub struct {
	Version   int
	Algo      pkix.AlgorithmIdentifier
	PublicKey []byte
	// optional attributes omitted.
}

type ecPublicKey struct {
	Version          int
	RawKey           []byte
	NamedCurveOID    asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	EncodedPublicKey asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func MarshalPKCS8PublicKey(key *PublicKey, paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	bytes, err := GetParamBytesPK(paramset, algorithm)
	if err != nil {
		return nil, err
	}
	fullbytes, err := GetFullBytesPK(bytes)
	if err != nil {
		return nil, err
	}

	pki, err := GenKey(key, paramset, algorithm)
	if err != nil {
		return nil, err
	}

	var privKey pkcs8Pub = pkcs8Pub{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: algorithm,
			Parameters: asn1.RawValue{
				FullBytes: fullbytes,
			},
		},
	}

	privKey.PublicKey, err = asn1.Marshal(ecPublicKey{
		Version:          1,
		RawKey:           key.Raw(),
		NamedCurveOID:    paramset,
		EncodedPublicKey: pki.PublicKey,
	})

	return asn1.Marshal(privKey)
}
