package cmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/spf13/cobra"
	"gotinca/xtime"
	"math/big"
	mathRand "math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVarP(&serverCmdVarOutputFilename, "output", "o", "-", flagUsageOutput)
	serverCmd.Flags().StringVarP(&serverCmdVarExpiryDuration, "duration", "d", "4y", flagUsageDuration)
	serverCmd.Flags().StringVarP(&serverCmdVarCryptoAlgorithm, "algorithm", "a", "ecdsa", flagUsageAlgorithm)
	serverCmd.Flags().StringVarP(&serverCmdVarCryptoBits, "key-bits", "b", "", flagUsageKeyBits)
	serverCmd.Flags().SortFlags = false
}

var serverCmdVarOutputFilename string
var serverCmdVarExpiryDuration string
var serverCmdVarCryptoAlgorithm string
var serverCmdVarCryptoBits string

// gotinca server <CA filename> <Domain/IPv4/IPv6> [Domain/IPv4/IPv6]... [flags]

var serverCmd = &cobra.Command{
	Use:   "server <CA filename> <Domain/IPv4/IPv6> [Domain/IPv4/IPv6]...",
	Short: "Server certificate",
	Args:  cobra.MatchAll(cobra.MinimumNArgs(2), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Parse duration
		duration, err := xtime.ParseDuration(serverCmdVarExpiryDuration)
		if err != nil {
			return fmt.Errorf("cannot parse duration: %s", err)
		}

		// Parse consecutive commands
		caFilename := args[0]
		sans := args[1:]

		var dns []string
		var ips []net.IP

		for _, san := range sans {
			san = strings.TrimSpace(san)

			err := checkDomain(san)
			if err == nil {
				dns = append(dns, san)
				continue
			}

			errIpv4 := checkIpv4(san)
			errIpv6 := checkIpv6(san)
			if errIpv4 == nil || errIpv6 == nil {
				ips = append(ips, net.ParseIP(san))
				continue
			}

			return fmt.Errorf("invalid Domain/IPv4/IPv6: `%s`", san)
		}

		props := serverCertProps{
			notAfter: time.Now().Add(duration),
			dns:      dns,
			ips:      ips,
		}

		caProps, err := createCaCertProps(caFilename)
		if err != nil {
			return err
		}
		return createServerCert(props, *caProps, serverCmdVarOutputFilename)
	},
}

type serverCertProps struct {
	notAfter time.Time
	dns      []string
	ips      []net.IP
}

func createServerCert(certProps serverCertProps, caProps caCertProps, outputCertChainFilename string) error {
	if outputCertChainFilename != "-" {
		_, err := os.Stat(outputCertChainFilename)
		if !os.IsNotExist(err) {
			return fmt.Errorf("file %s already exists", outputCertChainFilename)
		}
	}

	// Get Common Name (CN) from first DNS or IP
	var commonName string
	if len(certProps.dns) > 0 {
		commonName = certProps.dns[0]
	} else if len(certProps.ips) > 0 {
		commonName = certProps.ips[0].String()
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(mathRand.Int63()),
		Subject: pkix.Name{
			Organization: caProps.signerCert.Subject.Organization, // Get organization from issuer
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              certProps.notAfter,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames:    certProps.dns,
		IPAddresses: certProps.ips,
	}

	cryptoType, err := createCryptoType(serverCmdVarCryptoAlgorithm, serverCmdVarCryptoBits)
	if err != nil {
		return err
	}

	return createCertificate(SERVER, &template, *cryptoType, &caProps, outputCertChainFilename)
}
