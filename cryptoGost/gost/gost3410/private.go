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
	"errors"
	"fmt"
	"gostx509/cryptoGost/x509/pkix"
	"io"
	"math/big"
)

type PrivateKey struct {
	C   *Curve
	Key *big.Int
}

func NewPrivateKey(curve *Curve, raw []byte) (*PrivateKey, error) {
	pointSize := curve.PointSize()
	if len(raw) != pointSize {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", pointSize)
	}
	key := make([]byte, pointSize)
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("gogost/gost3410: zero private key")
	}
	return &PrivateKey{curve, k}, nil
}

func GenPrivateKey(curve *Curve, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, curve.PointSize())
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, err
	}
	return NewPrivateKey(curve, raw)
}

func (prv *PrivateKey) Raw() []byte {
	raw := pad(prv.Key.Bytes(), prv.C.PointSize())
	reverse(raw)
	return raw
}

func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.C.Exp(prv.Key, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, err
	}
	return &PublicKey{prv.C, x, y}, nil
}

func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	e := bytes2big(digest)
	e.Mod(e, prv.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, prv.C.PointSize())
	var err error
	var k *big.Int
	var r *big.Int
	d := big.NewInt(0)
	s := big.NewInt(0)
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, err
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.C.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.C.Exp(k, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, err
	}
	r.Mod(r, prv.C.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.Key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, prv.C.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	pointSize := prv.C.PointSize()
	return append(
		pad(s.Bytes(), pointSize),
		pad(r.Bytes(), pointSize)...,
	), nil
}

func (prv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return prv.SignDigest(digest, rand)
}

func (prv *PrivateKey) Public() crypto.PublicKey {
	pub, err := prv.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}

type PrivateKeyReverseDigest struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigest) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

func (prv *PrivateKeyReverseDigest) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	d := make([]byte, len(digest))
	copy(d, digest)
	reverse(d)
	return prv.Prv.Sign(rand, d, opts)
}

type PrivateKeyReverseDigestAndSignature struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigestAndSignature) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func MarshalPKCS8PrivateKey(key *PrivateKey, pub asn1.BitString, paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	bytes, err := GetParamBytesPK(paramset, algorithm)
	if err != nil {
		return nil, err
	}

	fullbytes, err := GetFullBytesPRK(bytes)
	if err != nil {
		return nil, err
	}

	var privKey pkcs8 = pkcs8{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: algorithm,
			Parameters: asn1.RawValue{
				FullBytes: fullbytes,
			},
		},
	}

	privKey.PrivateKey, err = asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.Key.FillBytes(make([]byte, (256+7)/8)),
		NamedCurveOID: paramset,
		PublicKey:     pub,
	})

	return asn1.Marshal(privKey)
}

func (prv *PrivateKeyReverseDigestAndSignature) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	d := make([]byte, len(digest))
	copy(d, digest)
	reverse(d)
	sign, err := prv.Prv.Sign(rand, d, opts)
	if err != nil {
		return sign, err
	}
	reverse(sign)
	return sign, err
}

func ExtractPublicKeyGOST(curve *Curve, privateKey *PrivateKey) (*PublicKey, error) {
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, err
	}

	publicKeyRaw := publicKey.Raw()

	publicKeyGost, err := NewPublicKey(curve, publicKeyRaw)
	if err != nil {
		return nil, err
	}

	return publicKeyGost, nil
}

type PrivateKeyInfo struct {
	Raw        asn1.RawContent
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey asn1.BitString
}

func GetFullBytesPRK(paramBytes []byte) ([]byte, error) {
	type A []byte

	ret, err := asn1.Marshal(A(paramBytes))
	if err != nil {
		return nil, err
	}
	ret[0] = 48

	return ret, nil
}

func GetParamBytesPRK(paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
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

func GetRawPRK(pub *PrivateKey, publicKeyAlgorithm pkix.AlgorithmIdentifier) ([]byte, *asn1.BitString, error) {
	//pkey, err := asn1.Marshal(pub.Raw())
	pkey := pub.Raw()
	//if err != nil {
	//	return nil, nil, err
	//}

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
