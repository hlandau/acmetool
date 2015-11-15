package solver

import "github.com/hlandau/acme/acmeapi"
import "github.com/hlandau/acme/interaction"
import "fmt"
import "net/mail"

func AssistedUpsertRegistration(cl *acmeapi.Client, interactionFunc interaction.Func) error {
	interactionFunc = defaultInteraction(interactionFunc)

	email := ""

	for {
		err := cl.UpsertRegistration()
		if err != nil {
			if e, ok := err.(*acmeapi.AgreementError); ok {
				res, err := interactionFunc(&interaction.Challenge{
					Title:        "Terms of Service Agreement Required",
					YesLabel:     "I Agree",
					NoLabel:      "Cancel",
					ResponseType: interaction.RTYesNo,
					UniqueID:     "acme-agreement:" + e.URI,
					Prompt:       "Do you agree to the Terms of Service? [Yn]",
					Body: fmt.Sprintf(`You must agree to the terms of service at the following URL to continue:

%s

Do you agree to the terms of service set out in the above document?`, e.URI),
				})
				if err != nil {
					return err
				}
				if !res.Cancelled {
					if email == "" {
						email, err = getEmail(interactionFunc)
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

func getEmail(interactionFunc interaction.Func) (string, error) {
	for {
		res, err := interactionFunc(&interaction.Challenge{
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

func defaultInteraction(interactionFunc interaction.Func) interaction.Func {
	if interactionFunc == nil {
		return interaction.Auto
	}
	return interactionFunc
}
