package cmd

const (
	// Documentation of CLI flags
	flagUsageCa = `To create an intermediate Certificate Authority (CA), you must specify the
root CA from which the intermediate CA will derive its trust.`
	flagUsageOutput   = `Output filename or "-" for stdout.`
	flagUsageDuration = `Duration how long a certificate is valid. It starts from the time the
certificate is issued. You can use these suffixes for duration:
  * s for seconds
  * m for minutes
  * h for hours
  * d for days
  * w for weeks
  * M for months
  * y for years.
You can also combine them, like: 300ms, 1.5h, or 2h45m.
`
	flagUsageAlgorithm = `Specify the cryptographic algorithm to be used. Possible values:
  * ecdsa
  * ed25519
  * rsa
`
	flagUsageKeyBits = `Define the size of the key used in the selected cryptographic algorithm.
Algorithm compatibility:
  * ecdsa: 256, 384 or 521.
  * ed25519: Fixed key size of 256 bits (no additional input required).
  * rsa: 2048, 3072 or 4096.`
)
