package template

import (
	"crypto/rand"
	"gost-x509/cryptoGost/gost/gost3410"
	"gost-x509/cryptoGost/gost/gost34112012256"
	gost509 "gost-x509/cryptoGost/x509"
	"gost-x509/cryptoGost/x509/pkix"
	"math/big"
	"time"
)

type X509Template struct {
	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string
}

func GetX509Template(pub *gost3410.PublicKey, x509template *X509Template, expiry time.Duration, isCA bool) (*gost509.Certificate, error) {
	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	// set expiry to around 10 years
	// round minute and backdate 5 minutes
	notBefore := time.Now().Round(time.Minute).Add(-5 * time.Minute).UTC()

	//basic template to use
	template := gost509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
		SignatureAlgorithm:    gost509.SHA256Gost,
	}
	template.IsCA = isCA
	template.KeyUsage |= gost509.KeyUsageDigitalSignature |
		gost509.KeyUsageKeyEncipherment | gost509.KeyUsageCertSign |
		gost509.KeyUsageCRLSign
	template.ExtKeyUsage = []gost509.ExtKeyUsage{
		gost509.ExtKeyUsageClientAuth,
		gost509.ExtKeyUsageServerAuth,
	}

	//set the organization for the subject
	subject := subjectTemplateAdditional(x509template)
	template.Subject = *subject

	hasher := gost34112012256.New()
	_, err := hasher.Write(pub.Raw())
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = hasher.Sum(nil)

	return &template, nil

}
func subjectTemplateAdditional(x509template *X509Template) *pkix.Name {
	return &pkix.Name{
		Country:            x509template.Country,
		Organization:       x509template.Organization,
		OrganizationalUnit: x509template.OrganizationalUnit,
		Locality:           x509template.Locality,
		Province:           x509template.Province,
		StreetAddress:      x509template.StreetAddress,
		PostalCode:         x509template.PostalCode,
		SerialNumber:       x509template.SerialNumber,
		CommonName:         x509template.CommonName,
	}
}
