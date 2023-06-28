package main

//
//import (
//	"crypto/rand"
//	"encoding/asn1"
//	"encoding/pem"
//	"gost-x509/cryptoGost/gost/gost3410"
//	"gost-x509/cryptoGost/gost/gost34112012256"
//	gost509 "gost-x509/cryptoGost/x509"
//	"gost-x509/cryptoGost/x509/pkix"
//	"io"
//	"log"
//	"math/big"
//	"os"
//	"time"
//)
//
//type publicKeyInfo struct {
//	Raw       asn1.RawContent
//	Algorithm pkix.AlgorithmIdentifier
//	PublicKey asn1.BitString
//}
//
//func main() {
//	GenerateX509Cert()
//	GeneratePrivateKey()
//}
//
//func GeneratePrivateKey() {
//	curve := gost3410.CurveIdtc26gost34102012256paramSetA
//	prvRaw := make([]byte, int(32))
//	_, err := io.ReadFull(rand.Reader, prvRaw)
//	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
//	if err != nil {
//		panic(err)
//	}
//
//	pub, err := prv.PublicKey()
//	if err != nil {
//		panic(err)
//	}
//
//	pki, err := gost3410.GenKey(pub, gost3410.OidTc26Gost34102012256ParamSetA, gost3410.OidTc26Gost34112012256)
//	if err != nil {
//		panic(err)
//	}
//
//	paramset := gost3410.OidTc26Gost34102012256ParamSetA
//	algorithm := gost3410.OidTc26Gost34102012256
//	prki, err := MarshalPKCS8PrivateKey(prv, pki.PublicKey, paramset, algorithm)
//	if err != nil {
//		panic(err)
//	}
//
//	flp, err := os.Create("private.key")
//	if err != nil {
//		panic(err)
//	}
//
//	pem.Encode(flp, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte(prki)})
//	log.Println("key create")
//
//	colorReset := "\033[0m"
//
//	colorGreen := "\033[32m"
//	log.Println(string(colorGreen), "DONE", string(colorReset))
//}
//
//func GenerateX509Cert() {
//	curve := gost3410.CurveIdtc26gost34102012256paramSetA
//	prvRaw := make([]byte, int(32))
//	_, err := io.ReadFull(rand.Reader, prvRaw)
//
//	prv, err := gost3410.NewPrivateKey(curve, prvRaw)
//	if err != nil {
//		panic(err)
//	}
//
//	pub, err := prv.PublicKey()
//	if err != nil {
//		panic(err)
//	}
//
//	cert, err := gen(prv, pub)
//	if err != nil {
//		panic(err)
//	}
//
//	fl, err := os.Create("gost_cert.pem")
//	if err != nil {
//		panic(err)
//	}
//
//	pem.Encode(fl, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
//
//}
//
//func MarshalPKCS8PrivateKey(key *gost3410.PrivateKey, pub asn1.BitString, paramset, algorithm asn1.ObjectIdentifier) ([]byte, error) {
//	type pkcs8 struct {
//		Version    int
//		Algo       pkix.AlgorithmIdentifier
//		PrivateKey []byte
//		// optional attributes omitted.
//	}
//	type ecPrivateKey struct {
//		Version       int
//		PrivateKey    []byte
//		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
//		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
//	}
//
//	var privKey pkcs8
//
//	bytes, err := gost3410.GetParamBytesPK(paramset, algorithm)
//	if err != nil {
//		return nil, err
//	}
//
//	fullbytes, err := gost3410.GetFullBytesPRK(bytes)
//	if err != nil {
//		return nil, err
//	}
//
//	privKey.Algo = pkix.AlgorithmIdentifier{
//		Algorithm: algorithm,
//		Parameters: asn1.RawValue{
//			FullBytes: fullbytes,
//		},
//	}
//
//	privateKey := make([]byte, (256+7)/8)
//	privKey.PrivateKey, err = asn1.Marshal(ecPrivateKey{
//		Version:       1,
//		PrivateKey:    key.Key.FillBytes(privateKey),
//		NamedCurveOID: paramset,
//		PublicKey:     pub,
//	})
//
//	return asn1.Marshal(privKey)
//}
//
//func gen(prv *gost3410.PrivateKey, pub *gost3410.PublicKey) ([]byte, error) {
//
//	ca := x509Template(pub)
//
//	caBytes, err := gost509.CreateCertificate(rand.Reader, &ca, &ca, pub, prv)
//	if err != nil {
//		return nil, err
//	}
//
//	return caBytes, err
//}
//
//func x509Template(pub *gost3410.PublicKey) gost509.Certificate {
//
//	// generate a serial number
//	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
//	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
//
//	// set expiry to around 10 years
//	expiry := 3650 * 24 * time.Hour
//	// round minute and backdate 5 minutes
//	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()
//
//	//basic template to use
//	template := gost509.Certificate{
//		SerialNumber:          serialNumber,
//		NotBefore:             notBefore,
//		NotAfter:              notBefore.Add(expiry).UTC(),
//		BasicConstraintsValid: true,
//		SignatureAlgorithm:    gost509.SHA256Gost,
//	}
//	template.IsCA = true
//	template.KeyUsage |= gost509.KeyUsageDigitalSignature |
//		gost509.KeyUsageKeyEncipherment | gost509.KeyUsageCertSign |
//		gost509.KeyUsageCRLSign
//	template.ExtKeyUsage = []gost509.ExtKeyUsage{
//		gost509.ExtKeyUsageClientAuth,
//		gost509.ExtKeyUsageServerAuth,
//	}
//	country, province, locality, orgUnit, streetAddress, postalCode, org, name := "a", "a", "a", "a", "a", "a", "a", "a"
//	//set the organization for the subject
//	subject := subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode)
//	subject.Organization = []string{org}
//	subject.CommonName = name
//
//	template.Subject = subject
//
//	hasher := gost34112012256.New()
//	_, err := hasher.Write(pub.Raw())
//	if err != nil {
//		panic(err)
//	}
//	dgst := hasher.Sum(nil)
//	template.SubjectKeyId = dgst
//
//	return template
//
//}
//func subjectTemplate() pkix.Name {
//	return pkix.Name{
//		Country:  []string{"US"},
//		Locality: []string{"San Francisco"},
//		Province: []string{"California"},
//	}
//}
//func subjectTemplateAdditional(country, province, locality, orgUnit, streetAddress, postalCode string) pkix.Name {
//	name := subjectTemplate()
//	if len(country) >= 1 {
//		name.Country = []string{country}
//	}
//	if len(province) >= 1 {
//		name.Province = []string{province}
//	}
//
//	if len(locality) >= 1 {
//		name.Locality = []string{locality}
//	}
//	if len(orgUnit) >= 1 {
//		name.OrganizationalUnit = []string{orgUnit}
//	}
//	if len(streetAddress) >= 1 {
//		name.StreetAddress = []string{streetAddress}
//	}
//	if len(postalCode) >= 1 {
//		name.PostalCode = []string{postalCode}
//	}
//	return name
//}
//
//func GenKey(key *gost3410.PublicKey) (publicKeyInfo, error) {
//	var publicKeyAlgorithm pkix.AlgorithmIdentifier
//
//	publicKeyAlgorithm.Parameters.Bytes = GetParamBytesPK()
//	publicKeyAlgorithm.Parameters.FullBytes = GetFullBytesPK(publicKeyAlgorithm.Parameters.Bytes)
//	raw, encodedPublicKey, err := GetRawPK(key, publicKeyAlgorithm)
//	if err != nil {
//		return publicKeyInfo{}, err
//	}
//	publicKeyAlgorithm.Algorithm = gost3410.Alg
//	publicKeyAlgorithm.Parameters.Tag = 16
//	publicKeyAlgorithm.Parameters.Class = 0
//	publicKeyAlgorithm.Parameters.IsCompound = true
//	pki := publicKeyInfo{raw, publicKeyAlgorithm, *encodedPublicKey}
//	return pki, nil
//}
//
//func GetFullBytesPK(paramBytes []byte) []byte {
//	type A []byte
//
//	ret, err := asn1.Marshal(A(paramBytes))
//	if err != nil {
//		panic(err)
//	}
//	ret[0] = 48
//
//	return ret
//}
//
//func GetParamBytesPK() []byte {
//	paramBytesPartOne, err := asn1.Marshal(gost3410.OidTc26Gost34102012256ParamSetA)
//	if err != nil {
//		panic(err)
//	}
//
//	paramBytesPartSecond, err := asn1.Marshal(gost3410.OidTc26Gost34112012256)
//	if err != nil {
//		panic(err)
//	}
//	var paramBytes []byte
//	paramBytes = append(paramBytes, paramBytesPartOne...)
//	paramBytes = append(paramBytes, paramBytesPartSecond...)
//
//	return paramBytes
//}
//
//func GetRawPK(pub *gost3410.PublicKey, publicKeyAlgorithm pkix.AlgorithmIdentifier) ([]byte, *asn1.BitString, error) {
//	pkey, err := asn1.Marshal(pub.Raw())
//	if err != nil {
//		return nil, nil, err
//	}
//
//	var algWFB []byte = []byte{48, 0}
//	resAlgWFB, err := asn1.Marshal(gost3410.Alg)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	resAlgWFB2, err := asn1.Marshal(publicKeyAlgorithm.Parameters.Bytes)
//	if err != nil {
//		return nil, nil, err
//	}
//	resAlgWFB2[0] = 48
//	algWFB = append(algWFB, resAlgWFB...)
//	algWFB = append(algWFB, resAlgWFB2...)
//	algWFB[1] = byte(len(algWFB) - 2)
//
//	var raw []byte = []byte{48, 0}
//	raw = append(raw, algWFB...)
//	encodedPublicKey := asn1.BitString{BitLength: len(pkey) * 8, Bytes: pkey}
//	EPKB, err := asn1.Marshal(encodedPublicKey)
//	if err != nil {
//		return nil, nil, err
//	}
//	raw = append(raw, EPKB...)
//	raw[1] = byte(len(raw) - 2)
//
//	return raw, &encodedPublicKey, nil
//}
