package solver

import (
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/interaction"
	"golang.org/x/net/context"
	"net/mail"
)

// Using the given client and interactor (or interaction.Auto if nil), register
// the client account if it does not already exist.
//
// The interactor is used to prompt for terms of service agreement, if
// agreement has not already been obtained. An e. mail address is prompted for.
func AssistedUpsertRegistration(cl *acmeapi.Client, interactor interaction.Interactor, ctx context.Context) error {
	interactor = defaultInteraction(interactor)

	email := ""

	reg := &acmeapi.Registration{}
	agreementURIs := map[string]struct{}{}
	for {
		err := cl.AgreeRegistration(reg, agreementURIs, ctx)
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
						if email == "-" {
							return fmt.Errorf("e. mail input cancelled")
						}
					}

					reg.AgreementURI = e.URI
					agreementURIs[e.URI] = struct{}{}
					if email != "" {
						reg.ContactURIs = []string{"mailto:" + email}
					}
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
			Body:         `Please enter an e. mail address where you can be reached. Although entering an e. mail address is optional, it is highly recommended.`,
			UniqueID:     "acme-enter-email",
		})
		if err != nil {
			return "", err
		}

		if res.Value == "" {
			return "", nil
		}

		if res.Cancelled {
			return "-", nil
		}

		addr, err := mail.ParseAddress(res.Value)
		if err != nil {
			if res.Noninteractive {
				// If the e. mail address specified was invalid but we received it from
				// a noninteractive source, don't loop or we will loop forever. Instead
				// just act like one wasn't specified.
				return "", nil
			}

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
