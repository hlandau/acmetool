package solver

import (
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/interaction"
	"net/mail"
)

func AssistedUpsertRegistration(cl *acmeapi.Client, interactor interaction.Interactor) error {
	interactor = defaultInteraction(interactor)

	email := ""

	for {
		err := cl.UpsertRegistration()
		if err != nil {
			if e, ok := err.(*acmeapi.AgreementError); ok {
				res, err := interactor.Prompt(&interaction.Challenge{
					Title:        "Terms of Service Agreement Required",
					YesLabel:     "I Agree",
					NoLabel:      "Cancel",
					ResponseType: interaction.RTYesNo,
					UniqueID:     "acme-agreement:" + e.URI,
					Prompt:       "Do you agree to the Terms of Service?",
					Body: fmt.Sprintf(`You must agree to the terms of service at the following URL to continue:

%s

Do you agree to the terms of service set out in the above document?`, e.URI),
				})
				if err != nil {
					return err
				}
				if !res.Cancelled {
					if email == "" {
						email, err = getEmail(interactor)
						if err != nil {
							return err
						}
						if email == "" {
							return fmt.Errorf("e. mail input cancelled")
						}
					}

					if cl.AccountInfo.AgreementURIs == nil {
						cl.AccountInfo.AgreementURIs = map[string]struct{}{}
					}
					cl.AccountInfo.AgreementURIs[e.URI] = struct{}{}
					cl.AccountInfo.ContactURIs = []string{"mailto:" + email}
					continue
				}
			}
		}

		return err
	}
}

func getEmail(interactor interaction.Interactor) (string, error) {
	for {
		res, err := interactor.Prompt(&interaction.Challenge{
			Title:        "E. Mail Address Required",
			ResponseType: interaction.RTLineString,
			Prompt:       "E. mail address: ",
			Body:         `Please enter an e. mail address where you can be reached.`,
			UniqueID:     "acme-enter-email",
		})
		if err != nil {
			return "", err
		}

		if res.Cancelled {
			return "", nil
		}

		addr, err := mail.ParseAddress(res.Value)
		if err != nil {
			continue
		}

		return addr.Address, nil
	}
}

func defaultInteraction(interactor interaction.Interactor) interaction.Interactor {
	if interactor == nil {
		return interaction.Auto
	}
	return interactor
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
