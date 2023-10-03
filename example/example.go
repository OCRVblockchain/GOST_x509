package main

import (
	"encoding/pem"
	x509 "github.com/OCRVblockchain/GOST_x509"
	"github.com/OCRVblockchain/GOST_x509/cryptoGost/gost/gost3410"
	"github.com/OCRVblockchain/GOST_x509/cryptoGost/template"
	"log"
	"os"
	"time"
)

func main() {
	GenerateCert()
	GeneratePrivateKey()
	GeneratePublicKey()
}

func GenerateCert() {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA
	tmpl := template.X509Template{
		Country:            []string{"US"},
		Organization:       []string{"ACME Inc."},
		OrganizationalUnit: []string{"Engineering"},
		Locality:           []string{"San Francisco"},
		Province:           []string{"CA"},
		StreetAddress:      []string{"123 Main St."},
		PostalCode:         []string{"94105"},
		SerialNumber:       "123456789",
		CommonName:         "www.example.com",
	}
	isCA := true
	expiry := 3650 * 24 * time.Hour

	cert, err := x509.GenerateX509Cert(curve, &tmpl, expiry, isCA)
	if err != nil {
		log.Fatalln(err)
		return
	}

	fl, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalln(err)
		return
	}

	pem.Encode(fl, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
}

func GeneratePrivateKey() {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA
	paramset := gost3410.OidTc26Gost34102012256ParamSetA
	algorithm := gost3410.OidTc26Gost34112012256

	privateKey, err := x509.GeneratePrivateKey(curve, paramset, algorithm)
	if err != nil {
		log.Fatalln(err)
		return
	}

	flp, err := os.Create("private.key")
	if err != nil {
		log.Fatalln(err)
		return
	}

	pem.Encode(flp, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte(privateKey)})
}

func GeneratePublicKey() {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA
	paramset := gost3410.OidTc26Gost34102012256ParamSetA
	algorithm := gost3410.OidTc26Gost34112012256

	privateKey, err := x509.GeneratePublicKey(curve, paramset, algorithm)
	if err != nil {
		log.Fatalln(err)
		return
	}

	flp, err := os.Create("public.key")
	if err != nil {
		log.Fatalln(err)
		return
	}

	pem.Encode(flp, &pem.Block{Type: "PUBLIC KEY", Bytes: []byte(privateKey)})
}
