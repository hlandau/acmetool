package acmeendpoints

var (
	// Let's Encrypt (Live)
	LetsEncryptLive = Endpoint{
		Code:                   "LetsEncryptLive",
		Title:                  "Let's Encrypt (Live)",
		DirectoryURL:           "https://acme-v01.api.letsencrypt.org/directory",
		OCSPURLRegexp:          `^http://ocsp\.int-[^.]+\.letsencrypt\.org\.?(/.*)?$`,
		CertificateURLRegexp:   `^https://acme-v01\.api\.letsencrypt\.org\.?/acme/cert/.*$`,
		CertificateURLTemplate: `https://acme-v01.api.letsencrypt.org/acme/cert/{{.Certificate.SerialNumber|printf "%036x"}}`,
	}

	// Let's Encrypt (Staging)
	LetsEncryptStaging = Endpoint{
		Code:                   "LetsEncryptStaging",
		Title:                  "Let's Encrypt (Staging)",
		DirectoryURL:           "https://acme-staging.api.letsencrypt.org/directory",
		OCSPURLRegexp:          `^http://ocsp\.(staging|stg-int)-[^.]+\.letsencrypt\.org\.?(/.*)?$`,
		CertificateURLRegexp:   `^https://acme-staging\.api\.letsencrypt\.org\.?/acme/cert/.*$`,
		CertificateURLTemplate: `https://acme-staging.api.letsencrypt.org/acme/cert/{{.Certificate.SerialNumber|printf "%036x"}}`,
	}
)

// Suggested default endpoint.
var DefaultEndpoint = &LetsEncryptLive

var builtinEndpoints = []*Endpoint{
	&LetsEncryptLive,
	&LetsEncryptStaging,
}
