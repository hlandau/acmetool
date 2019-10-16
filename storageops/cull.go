package storageops

import "github.com/hlandau/acmetool/storage"

func Cull(s storage.Store, simulate bool) error {
	certificatesToCull := map[string]*storage.Certificate{}

	// Relink before culling.
	err := Relink(s)
	if err != nil {
		return err
	}

	// Select all certificates.
	s.VisitCertificates(func(c *storage.Certificate) error {
		certificatesToCull[c.ID()] = c
		return nil
	})

	// Unselect any certificate which is currently referenced.
	s.VisitPreferredCertificates(func(hostname string, c *storage.Certificate) error {
		delete(certificatesToCull, c.ID())
		return nil
	})

	// Now delete any certificate which is not generally valid.
	for certID, c := range certificatesToCull {
		if CertificateGenerallyValid(c) {
			continue
		}

		if simulate {
			log.Noticef("would delete certificate %s", certID)
		} else {
			log.Noticef("deleting certificate %s", certID)
			err := s.RemoveCertificate(certID)
			log.Errore(err, "failed to delete certificate ", certID)
		}
	}

	return nil
}
