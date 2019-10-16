package solver

import (
	"fmt"
	"github.com/hlandau/acmetool/interaction"
	"golang.org/x/net/context"
	"gopkg.in/hlandau/acmeapi.v2"
	"net/mail"
)

// Using the given client, account and interactor (or interaction.Auto if nil),
// register the client account if it does not already exist. Does not do anything
// and does NOT update the registration if the account is already registered.
//
// The interactor is used to prompt for terms of service agreement, if
// agreement has not already been obtained. An e. mail address is prompted for.
func AssistedRegistration(ctx context.Context, cl *acmeapi.RealmClient, acct *acmeapi.Account, interactor interaction.Interactor) error {
	interactor = defaultInteraction(interactor)

	// We know for a fact the account has already been registered because we know
	// its URL. Don't do anything.
	if acct.URL != "" {
		return nil
	}

	// See if the account has already been registered. If so, the URL gets stored
	// in acct.URL and we're done.
	err := cl.LocateAccount(ctx, acct)
	if err == nil {
		return nil
	}

	// Check that the error that occured was a not found error.
	he, ok := err.(*acmeapi.HTTPError)
	if !ok {
		return err
	}
	if he.Problem == nil || he.Problem.Type != "urn:ietf:params:acme:error:accountDoesNotExist" {
		return err
	}

	// Get the directory metadata so we can get the terms of service URL.
	meta, err := cl.GetMeta(ctx)
	if err != nil {
		return err
	}

	// Prompt for ToS agreement if required.
	acct.TermsOfServiceAgreed = false
	if meta.TermsOfServiceURL != "" {
		res, err := interactor.Prompt(&interaction.Challenge{
			Title:        "Terms of Service Agreement Required",
			YesLabel:     "I Agree",
			NoLabel:      "Cancel",
			ResponseType: interaction.RTYesNo,
			UniqueID:     "acme-agreement:" + meta.TermsOfServiceURL,
			Prompt:       "Do you agree to the Terms of Service?",
			Body: fmt.Sprintf(`You must agree to the terms of service at the following URL to continue:

%s

Do you agree to the terms of service set out in the above document?`, meta.TermsOfServiceURL),
		})
		if err != nil {
			return err
		}

		if res.Cancelled {
			return fmt.Errorf("terms of service agreement is required, but user declined")
		}

		acct.TermsOfServiceAgreed = true
	}

	// Get e. mail.
	email, err := getEmail(interactor)
	if err != nil {
		return err
	}
	if email == "-" {
		return fmt.Errorf("e. mail input cancelled")
	}

	if email != "" {
		acct.ContactURIs = []string{"mailto:" + email}
	}

	// Do the registration.
	err = cl.RegisterAccount(ctx, acct)
	if err != nil {
		return err
	}

	return nil
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
