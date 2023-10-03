package gost_x509

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/OCRVblockchain/GOST_x509/cryptoGost/gost/gost3410"
	"github.com/OCRVblockchain/GOST_x509/cryptoGost/template"
	x509 "github.com/OCRVblockchain/GOST_x509/cryptoGost/x509"
	"io"
	"time"
)

type GenerateCertRequest struct {
	Curve        *gost3410.Curve
	X509template *template.X509Template
	IsCA         bool
	Expiry       time.Duration
}

func GenerateX509Cert(curve *gost3410.Curve, x509template *template.X509Template, expiry time.Duration, isCA bool) ([]byte, error) {
	prvRaw := make([]byte, int(32))
	_, err := io.ReadFull(rand.Reader, prvRaw)
	if err != nil {
		return nil, err
	}

	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, err
	}

	pub, err := prv.PublicKey()
	if err != nil {
		return nil, err
	}

	ca, err := template.GetX509Template(pub, x509template, expiry, isCA)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, prv)
	if err != nil {
		return nil, err
	}

	return caBytes, err
}

func GeneratePrivateKey(curve *gost3410.Curve, paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	prvRaw := make([]byte, int(32))
	_, err := io.ReadFull(rand.Reader, prvRaw)

	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, err
	}

	pub, err := prv.PublicKey()
	if err != nil {
		return nil, err
	}

	pki, err := gost3410.GenKey(pub, paramset, algorithm)
	if err != nil {
		return nil, err
	}

	prki, err := gost3410.MarshalPKCS8PrivateKey(prv, pki.PublicKey, paramset, algorithm)
	if err != nil {
		return nil, err
	}

	return prki, nil
}

func GeneratePublicKey(curve *gost3410.Curve, paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	prvRaw := make([]byte, int(32))
	_, err := io.ReadFull(rand.Reader, prvRaw)

	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		return nil, err
	}

	pk, err := gost3410.ExtractPublicKeyGOST(curve, prv)
	if err != nil {
		return nil, err
	}

	prki, err := gost3410.MarshalPKCS8PublicKey(pk, paramset, algorithm)
	if err != nil {
		return nil, err
	}

	return prki, nil
}
