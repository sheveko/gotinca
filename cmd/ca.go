package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/spf13/cobra"
	"gotinca/xtime"
	"math/big"
	mathRand "math/rand"
	"os"
	"time"
)

func init() {
	rootCmd.AddCommand(caCmd)

	caCmd.Flags().StringVarP(&caCmdVarCertauthorityFilename, "ca", "c", "", flagUsageCa)
	caCmd.Flags().StringVarP(&caCmdVarOutputFilename, "output", "o", "-", flagUsageOutput)
	caCmd.Flags().StringVarP(&caCmdVarExpiryDuration, "duration", "d", "4y", flagUsageDuration)
	caCmd.Flags().StringVarP(&caCmdVarCryptoAlgorithm, "algorithm", "a", "ecdsa", flagUsageAlgorithm)
	caCmd.Flags().StringVarP(&caCmdVarCryptoBits, "key-bits", "b", "", flagUsageKeyBits)
	caCmd.Flags().SortFlags = false
}

var caCmdVarCertauthorityFilename string
var caCmdVarOutputFilename string
var caCmdVarExpiryDuration string
var caCmdVarCryptoAlgorithm string
var caCmdVarCryptoBits string

// gotinca ca <Common name> [Organization] [flags]

var caCmd = &cobra.Command{
	Use:   "ca <Common name> [Organization]",
	Short: "Certificate authority",
	Args:  cobra.MatchAll(cobra.MatchAll(cobra.MinimumNArgs(1), cobra.MaximumNArgs(2)), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse duration
		duration, err := xtime.ParseDuration(caCmdVarExpiryDuration)
		if err != nil {
			return fmt.Errorf("cannot parse duration: %s", err)
		}

		// Parse consecutive commands
		cliCommonName := args[0]

		var cliOrganization []string
		if len(args) > 1 {
			cliOrganization = []string{args[1]}
		} else {
			cliOrganization = []string{}
		}

		clientProps := clientCertProps{
			subjectOrganization: cliOrganization,
			subjectCommonName:   cliCommonName,
			notAfter:            time.Now().Add(duration),
		}

		if caCmdVarCertauthorityFilename != "" {
			return createIntermediateCaCert(clientProps, caCmdVarCertauthorityFilename, caCmdVarOutputFilename)
		} else {
			return createRootCa(clientProps, caCmdVarOutputFilename)
		}
	},
}

type caCertProps struct {
	signerCert *x509.Certificate
	signerKey  any
	chainCert  []x509.Certificate
}

func createRootCa(clientProps clientCertProps, outputCertChainFilename string) error {
	return createCaCert(clientProps, nil, outputCertChainFilename)
}

// Create an intermediate Certificate Authority (CA) based on a signer
func createIntermediateCaCert(clientProps clientCertProps, certAuthorityFilename string, outputCertChainFilename string) error {
	caProps, err := createCaCertProps(certAuthorityFilename)
	if err != nil {
		return err
	}

	return createCaCert(clientProps, caProps, outputCertChainFilename)
}

func createCaCert(clientProps clientCertProps, caProps *caCertProps, outputCertChainFilename string) error {
	if outputCertChainFilename != "-" {
		_, err := os.Stat(outputCertChainFilename)
		if !os.IsNotExist(err) {
			return fmt.Errorf("file %s already exists", outputCertChainFilename)
		}
	}

	var serialNumber int64
	var issuer pkix.Name
	subject := pkix.Name{
		Organization: clientProps.subjectOrganization,
		CommonName:   clientProps.subjectCommonName,
	}

	if isCreateRootCa(caProps) {
		serialNumber = 0
		issuer = pkix.Name{
			Organization: clientProps.subjectOrganization,
			CommonName:   clientProps.subjectCommonName,
		}
	} else {
		serialNumber = mathRand.Int63()
		issuer = pkix.Name{}
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Issuer:                issuer,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              clientProps.notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	cryptoType, err := createCryptoType(caCmdVarCryptoAlgorithm, caCmdVarCryptoBits)
	if err != nil {
		return err
	}

	// create the CA
	var certaType CertificateType
	if isCreateRootCa(caProps) {
		certaType = CA
	} else {
		certaType = CAINTERMEDIATE
	}

	return createCertificate(certaType, &template, *cryptoType, caProps, outputCertChainFilename)
}
