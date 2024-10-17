package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func printCert(certificate x509.Certificate) string {
	var s []string
	s = append(s, fmt.Sprintf("Issuer: %s\n", printName(certificate.Issuer)))
	s = append(s, fmt.Sprintf("Subject: %s", printName(certificate.Subject)))

	if len(certificate.DNSNames) > 0 {
		s = append(s, fmt.Sprintf("/SAN-DNS=%s", strings.Join(certificate.DNSNames, ",")))
	}

	if len(certificate.IPAddresses) > 0 {
		ips := strings.Join(Map(certificate.IPAddresses, func(ip net.IP) string {
			return ip.String()
		}), ",")

		s = append(s, fmt.Sprintf("/SAN-IP=%s", ips))
	}

	s = append(s, "\n")
	return strings.Join(s, "")
}

func printName(name pkix.Name) string {
	var s []string

	if len(name.CommonName) > 0 {
		s = append(s, "CN="+name.CommonName)
	}
	if name.Country != nil {
		s = append(s, "C="+strings.Join(name.Country, ","))
	}
	if name.Organization != nil {
		s = append(s, "O="+strings.Join(name.Organization, ","))
	}
	if name.OrganizationalUnit != nil {
		s = append(s, "OU="+strings.Join(name.OrganizationalUnit, ","))
	}
	if name.Locality != nil {
		s = append(s, "L="+strings.Join(name.Locality, ","))
	}
	if name.Province != nil {
		s = append(s, "ST="+strings.Join(name.Province, ","))
	}
	if name.StreetAddress != nil {
		s = append(s, "STREET="+strings.Join(name.StreetAddress, ","))
	}
	if name.PostalCode != nil {
		s = append(s, "POSTALCODE="+strings.Join(name.PostalCode, ","))
	}
	if len(name.SerialNumber) > 0 {
		s = append(s, "SERIALNUMBER="+name.SerialNumber)
	}

	return strings.Join(s, "/")
}

// Check if *name* is a domain. If not raise an error.
// Inspired by [github.com/chmike/domain](https://github.com/chmike/domain/blob/2c0257be60a1d04ae76940e4525a677c92d2e967/check.go)
func checkDomain(name string) error {
	if len(name) == 0 {
		return errors.New("domain name is empty")
	}
	if name[len(name)-1] == '.' {
		return errors.New("domain name must not end with a dot")
	}

	var l int
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			// check domain labels validity
			switch {
			case i == l:
				return fmt.Errorf("domain has an empty label at offset %d", l)
			case i == len(name)-1:
				return fmt.Errorf("domain must not end with %U", b)
			case i-l > 63:
				return fmt.Errorf("domain byte length of label '%s' is %d, can't exceed 63", name[l:i], i-l)
			case name[l] == '-':
				return fmt.Errorf("domain label '%s' at offset %d begins with a hyphen", name[l:i], l)
			case name[i-1] == '-':
				return fmt.Errorf("domain label '%s' at offset %d ends with a hyphen", name[l:i], l)
			}
			l = i + 1
			continue
		}

		if b == '*' && i == 0 {
			continue
		}

		// test label character validity, note: tests are ordered by decreasing validity frequency
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			// show the printable Unicode character starting at byte offset i
			c, _ := utf8.DecodeRuneInString(name[i:])
			if c == utf8.RuneError {
				return fmt.Errorf("domain has invalid rune at offset %d", i)
			}
			return fmt.Errorf("domain has invalid character '%c' at offset %d", c, i)
		}
	}

	// check top level domain validity
	switch {
	case len(name)-l > 63:
		return fmt.Errorf("domain's top level domain '%s' has byte length %d, can't exceed 63", name[l:], len(name)-l)
	case name[l] == '-':
		return fmt.Errorf("domain's top level domain '%s' at offset %d begin with a hyphen", name[l:], l)
	case name[len(name)-1] == '-':
		return fmt.Errorf("domain's top level domain '%s' at offset %d ends with a hyphen", name[l:], l)
	case name[l] >= '0' && name[l] <= '9':
		return fmt.Errorf("domain's top level domain '%s' at offset %d begins with a digit", name[l:], l)
	}

	return nil
}

const ipv4Regex = `(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`

func checkIpv4(ipv4 string) error {
	matched, _ := regexp.MatchString(ipv4Regex, ipv4)
	if !matched {
		return errors.New("invalid IPv4 address")
	}
	return nil
}

const ipv6Regex = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`

func checkIpv6(ipv6 string) error {
	matched, _ := regexp.MatchString(ipv6Regex, ipv6)
	if !matched {
		return errors.New("invalid IPv6 address")
	}
	return nil
}

func createCaCertProps(certAuthorityFilename string) (*caCertProps, error) {
	caContentPem, err := os.ReadFile(certAuthorityFilename)
	if err != nil {
		return nil, fmt.Errorf(`cannot read CertAuthority file: "%s"`, certAuthorityFilename)
	}

	var certificates []*x509.Certificate
	var signerKey *rsa.PrivateKey

	for block, rest := pem.Decode(caContentPem); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("cannot read CertAuthority file: %s", err)
			}
			certificates = append(certificates, certificate)
		// TODO: What happens with multiple certificates? Parents?
		case "PRIVATE KEY":
			if signerKey != nil {
				return nil, errors.New("found multiple private keys in file; take care, there is only one private key")
			}
			signerKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("cannot read CertAuthority file: %s", err)
			}
		default:
			return nil, fmt.Errorf("unknown certificate block type: %s", block.Type)
		}
	}

	// Find correct signerCert from private key
	if signerKey == nil {
		return nil, errors.New("missing private key")
	}

	var signerCert *x509.Certificate
	var pkiChain []x509.Certificate

	for _, certificate := range certificates {
		if reflect.DeepEqual(&signerKey.PublicKey, certificate.PublicKey) {
			signerCert = certificate
		} else {
			pkiChain = append(pkiChain, *certificate)
		}
	}
	if signerCert == nil {
		return nil, errors.New("missing certificate")
	}

	return &caCertProps{
		signerCert: signerCert,
		signerKey:  signerKey,
		chainCert:  pkiChain,
	}, nil
}

type CertificateType uint8

const (
	CA CertificateType = iota
	CAINTERMEDIATE
	SERVER
	CLIENT
)

type KeyType uint8

const (
	RSA KeyType = iota
	ED25519
	ECDSA
)

type CryptoType struct {
	keyType KeyType

	ecdsaCurve elliptic.Curve
	rsaKeyBits int
}

// createCryptoType Creates a CryptoType from CLI paramters algorithm and keyBits.
func createCryptoType(algorithm string, keyBits string) (*CryptoType, error) {
	var cryptoType CryptoType

	switch strings.ToLower(algorithm) {
	case "ecdsa":
		cryptoType.keyType = ECDSA
		if keyBits == "224" {
			cryptoType.ecdsaCurve = elliptic.P224()
		} else if keyBits == "256" {
			cryptoType.ecdsaCurve = elliptic.P256()
		} else if keyBits == "384" {
			cryptoType.ecdsaCurve = elliptic.P384()
		} else if keyBits == "521" || keyBits == "" { // Default value
			cryptoType.ecdsaCurve = elliptic.P521()
		} else {
			return nil, fmt.Errorf(`unsupported key-bits: %s; with algorithm "ecdsa" one of [224, 256, 384, 521] is allowed`, keyBits)
		}

	case "ed25519":
		cryptoType.keyType = ED25519
		if keyBits != "" {
			return nil, fmt.Errorf(`unsupported key-bits: %s; with algorithm "ed25519" key-bits has no option`, keyBits)
		}

	case "rsa":
		cryptoType.keyType = RSA
		if !slices.Contains([]string{"1024", "2048", "4096", "8192"}, keyBits) {
			return nil, fmt.Errorf(`unsupported key-bits: %s; with algorithm "rsa" one of [1024, 2048, 4096, 8192] is allowed`, keyBits)
		} else if keyBits == "" {
			keyBits = "4096"
		}
		cryptoType.rsaKeyBits, _ = strconv.Atoi(keyBits)

	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}

	return &cryptoType, nil
}

type CertKeyBundle struct {
	certificate []byte
	key         any
}

func createCertificate(certificateType CertificateType, certificateTemplate *x509.Certificate, cryptoType CryptoType, caProps *caCertProps, outputCertChainFilename string) error {

	// Ask and validate properties before creating new cert
	switch certificateType {
	case CA:
		fmt.Fprintln(os.Stderr, "Create CA certiticate")
	case CAINTERMEDIATE:
		fmt.Fprintln(os.Stderr, "Create intermediate CA certiticate")
	case SERVER:
		fmt.Fprintln(os.Stderr, "Create server certiticate")
	case CLIENT:
		fmt.Fprintln(os.Stderr, "Create client certiticate")
	}

	if isCreateRootCa(caProps) {
		fmt.Fprintln(os.Stderr, "Issuer: (same as subject)")
		fmt.Fprintf(os.Stderr, "  Valid from:   %s\n", certificateTemplate.NotBefore.Format(time.DateTime))
		fmt.Fprintf(os.Stderr, "  Valid until:  %s\n", certificateTemplate.NotAfter.Format(time.DateTime))
		fmt.Fprintf(os.Stderr, "  Organization: %s\n", strings.Join(certificateTemplate.Subject.Organization, ","))
		fmt.Fprintf(os.Stderr, "  Common name:  %s\n", certificateTemplate.Subject.CommonName)
	} else {
		fmt.Fprintln(os.Stderr, "Issuer:")
		fmt.Fprintf(os.Stderr, "  Valid from:   %s\n", caProps.signerCert.NotBefore.Format(time.DateTime))
		fmt.Fprintf(os.Stderr, "  Valid until:  %s\n", caProps.signerCert.NotAfter.Format(time.DateTime))
		fmt.Fprintf(os.Stderr, "  Organization: %s\n", strings.Join(caProps.signerCert.Subject.Organization, ","))
		fmt.Fprintf(os.Stderr, "  Common name:  %s\n", caProps.signerCert.Subject.CommonName)
	}

	fmt.Fprintln(os.Stderr, "Subject:")
	fmt.Fprintf(os.Stderr, "  Valid from:   %s\n", certificateTemplate.NotBefore.Format(time.DateTime))
	fmt.Fprintf(os.Stderr, "  Valid until:  %s\n", certificateTemplate.NotAfter.Format(time.DateTime))
	fmt.Fprintf(os.Stderr, "  Organization: %s\n", strings.Join(certificateTemplate.Subject.Organization, ","))
	fmt.Fprintf(os.Stderr, "  Common name:  %s\n", certificateTemplate.Subject.CommonName)
	if len(certificateTemplate.DNSNames) > 0 {
		fmt.Fprintf(os.Stderr, "  SAN DNS:      %s\n", strings.Join(certificateTemplate.DNSNames, ","))
	}
	if len(certificateTemplate.IPAddresses) > 0 {
		fmt.Fprintf(os.Stderr, "  SAN IP:       %s\n", strings.Join(Map(certificateTemplate.IPAddresses, func(ip net.IP) string {
			return ip.String()
		}), ","))
	}

	fmt.Fprint(os.Stderr, "\nCorrect? (y|N): ")
	cliReader := bufio.NewScanner(os.Stdin)
	cliReader.Scan()
	cliText := cliReader.Text()
	if strings.ToLower(strings.TrimSpace(cliText)) != "y" {
		return nil
	}
	fmt.Fprint(os.Stderr, "\n")

	// create our private and public key
	var certKeyBundle *CertKeyBundle
	var err error
	switch cryptoType.keyType {
	case ECDSA:
		certKeyBundle, err = createCertificateEcdsa(certificateTemplate, cryptoType.ecdsaCurve, caProps)
	case ED25519:
		certKeyBundle, err = createCertificateEd25519(certificateTemplate, caProps)
	case RSA:
		certKeyBundle, err = createCertificateRsa(certificateTemplate, cryptoType.rsaKeyBits, caProps)
	default:
		panic("unhandled default case")
	}

	if err != nil {
		return fmt.Errorf("cannot create certificate: %s", err)
	}

	cert, _ := x509.ParseCertificate(certKeyBundle.certificate)

	// PEM encode chain
	// 1. Private key
	// 2. Certificate
	// 3. Parent certificate (if is not the same as Certificate)

	var outputCertChainFile *os.File
	if outputCertChainFilename == "-" {
		outputCertChainFile = os.Stdout
	} else {
		outputCertChainFile, err = os.Create(outputCertChainFilename)
		if err != nil {
			return fmt.Errorf("cannot write file \"%s\": %s", outputCertChainFilename, err)
		}
	}
	defer outputCertChainFile.Close()

	// Private key
	outputCertChainFile.WriteString(printCert(*cert))
	keyBytes, err := x509.MarshalPKCS8PrivateKey(certKeyBundle.key)
	err = pem.Encode(outputCertChainFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	if err != nil {
		return fmt.Errorf("cannot encode private key: %s", err.Error())
	}

	// Certificate
	outputCertChainFile.WriteString(printCert(*cert))
	err = pem.Encode(outputCertChainFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certKeyBundle.certificate,
	})
	if err != nil {
		return fmt.Errorf("cannot encode certificate: %s", err.Error())
	}

	// Parent certificate
	if !isCreateRootCa(caProps) {
		outputCertChainFile.WriteString(printCert(*caProps.signerCert))

		err = pem.Encode(outputCertChainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caProps.signerCert.Raw,
		})
		if err != nil {
			return fmt.Errorf("cannot encode certificate: %s", err.Error())
		}

		for _, certificate := range caProps.chainCert {
			outputCertChainFile.WriteString(printCert(certificate))

			err = pem.Encode(outputCertChainFile, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificate.Raw,
			})
			if err != nil {
				return fmt.Errorf("cannot encode certificate: %s", err.Error())
			}
		}
	}

	return nil
}

func createCertificateEcdsa(certficateTemplate *x509.Certificate, ecdsaCurve elliptic.Curve, caProps *caCertProps) (*CertKeyBundle, error) {
	key, err := ecdsa.GenerateKey(ecdsaCurve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot create private key: %s", err.Error())
	}

	var parentCa *x509.Certificate
	var parentCaKey any

	if isCreateRootCa(caProps) {
		parentCa = certficateTemplate
		parentCaKey = key
	} else {
		parentCa = caProps.signerCert
		parentCaKey = caProps.signerKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certficateTemplate, parentCa, &key.PublicKey, parentCaKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create certificate: %s", err.Error())
	}

	return &CertKeyBundle{certificate: certBytes, key: key}, nil

}

func createCertificateEd25519(certficateTemplate *x509.Certificate, caProps *caCertProps) (*CertKeyBundle, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot create private key: %s", err.Error())
	}

	var parentCa *x509.Certificate
	var parentCaKey any

	if isCreateRootCa(caProps) {
		parentCa = certficateTemplate
		parentCaKey = privKey
	} else {
		parentCa = caProps.signerCert
		parentCaKey = caProps.signerKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certficateTemplate, parentCa, pubKey, parentCaKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create certificate: %s", err.Error())
	}

	return &CertKeyBundle{certificate: certBytes, key: privKey}, nil
}

func createCertificateRsa(certficateTemplate *x509.Certificate, keyBits int, caProps *caCertProps) (*CertKeyBundle, error) {
	// create our private and public key
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("cannot create private key: %s", err.Error())
	}

	var parentCa *x509.Certificate
	var parentCaKey any

	if isCreateRootCa(caProps) {
		parentCa = certficateTemplate
		parentCaKey = key
	} else {
		parentCa = caProps.signerCert
		parentCaKey = caProps.signerKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certficateTemplate, parentCa, &key.PublicKey, parentCaKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create certificate: %s", err.Error())
	}

	return &CertKeyBundle{certificate: certBytes, key: key}, nil
}

func isCreateRootCa(caProps *caCertProps) bool {
	return caProps == nil || caProps.signerCert == nil || caProps.signerKey == nil
}

func Map[T, V any](ts []T, fn func(T) V) []V {
	result := make([]V, len(ts))
	for i, t := range ts {
		result[i] = fn(t)
	}
	return result
}
