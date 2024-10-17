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
	rootCmd.AddCommand(clientCmd)

	clientCmd.Flags().StringVarP(&clientCmdVarOutputFilename, "output", "o", "-", flagUsageOutput)
	clientCmd.Flags().StringVarP(&clientCmdVarExpiryDuration, "duration", "d", "4y", flagUsageDuration)
	clientCmd.Flags().StringVarP(&clientCmdVarCryptoAlgorithm, "algorithm", "a", "ecdsa", flagUsageAlgorithm)
	clientCmd.Flags().StringVarP(&clientCmdVarCryptoBits, "key-bits", "b", "", flagUsageKeyBits)
	clientCmd.Flags().SortFlags = false
}

var clientCmdVarOutputFilename string
var clientCmdVarExpiryDuration string
var clientCmdVarCryptoAlgorithm string
var clientCmdVarCryptoBits string

// gotinca client <CA filename> <Common name> [flags]

var clientCmd = &cobra.Command{
	Use:   "client <CA filename> <Common name>",
	Short: "Client certificate",
	Args:  cobra.MatchAll(cobra.ExactArgs(2), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse duration
		duration, err := xtime.ParseDuration(clientCmdVarExpiryDuration)
		if err != nil {
			return fmt.Errorf("cannot parse duration: %s", err)
		}

		// Parse consecutive commands
		caFilename := args[0]
		commonName := args[1]

		caProps, err := createCaCertProps(caFilename)
		if err != nil {
			return err
		}
		clientProps := clientCertProps{
			subjectOrganization: caProps.signerCert.Subject.Organization, // Get organization from issuer
			subjectCommonName:   commonName,
			notAfter:            time.Now().Add(duration),
		}

		return createClientCert(clientProps, *caProps, clientCmdVarOutputFilename)
	},
}

type clientCertProps struct {
	subjectOrganization []string
	subjectCommonName   string
	notAfter            time.Time
}

func createClientCert(clientProps clientCertProps, caProps caCertProps, outputCertChainFilename string) error {
	if outputCertChainFilename != "-" {
		_, err := os.Stat(outputCertChainFilename)
		if !os.IsNotExist(err) {
			return fmt.Errorf("file %s already exists", outputCertChainFilename)
		}
	}

	// Create metadata of certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(mathRand.Int63()),
		Subject: pkix.Name{
			Organization: clientProps.subjectOrganization,
			CommonName:   clientProps.subjectCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              clientProps.notAfter,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cryptoType, err := createCryptoType(clientCmdVarCryptoAlgorithm, clientCmdVarCryptoBits)
	if err != nil {
		return err
	}
	return createCertificate(CLIENT, &template, *cryptoType, &caProps, outputCertChainFilename)
}
