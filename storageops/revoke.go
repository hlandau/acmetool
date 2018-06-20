package storageops

import (
	"fmt"
	"github.com/hlandau/acmetool/storage"
	"github.com/hlandau/acmetool/util"
)

func RevokeByCertificateOrKeyID(s storage.Store, id string) error {
	c := s.CertificateByID(id)
	if c == nil {
		return revokeByKeyID(s, id)
	}

	if c.Revoked {
		log.Warnf("%v already revoked", c)
		return nil
	}

	c.RevocationDesired = true
	return s.SaveCertificate(c)
}

func revokeByKeyID(s storage.Store, keyID string) error {
	k := s.KeyByID(keyID)
	if k == nil {
		return fmt.Errorf("cannot find certificate or key with given ID: %q", keyID)
	}

	var merr util.MultiError
	s.VisitCertificates(func(c *storage.Certificate) error {
		if c.Key != k {
			return nil // continue
		}

		err := RevokeByCertificateOrKeyID(s, c.ID())
		if err != nil {
			merr = append(merr, fmt.Errorf("failed to mark %v for revocation: %v", c, err))
		}

		return nil
	})

	if len(merr) > 0 {
		return merr
	}

	return nil
}
