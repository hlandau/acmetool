package acmeapi

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
)

func TestStatus(t *testing.T) {
	var s Status
	err := json.Unmarshal([]byte(`"pending"`), &s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if s != "pending" || !s.Valid() || s.Final() {
		t.Fatal()
	}
	err = json.Unmarshal([]byte(`"f9S0"`), &s)
	if err == nil {
		t.Fatal()
	}
}

func TestChallenge(t *testing.T) {
	const cJSON = `{
  "type": "http-01",
  "status": "invalid",
  "error": {
    "type": "urn:acme:error:caa",
    "detail": "CAA record for mymonash2021.conference.monash.edu prevents issuance",
    "status": 403
  },
  "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/wL4hNlUUJtGoMp6QeavoaAZjbqmBgJk2FMpOSC1aoIU/2676511905",
  "token": "GMgoj5xYX7qSIfN9GdmyqhdAHYrCco_Md9kKrT8v0jE",
  "keyAuthorization": "GMgoj5xYX7qSIfN9GdmyqhdAHYrCco_Md9kKrT8v0jE.QRRvz3cNxWGJObT4gl6G9ZNx-4cXE2eK81kX5lpYzmo",
  "validationRecord": [
    {
      "url": "http://mysite.foo.com/.well-known/acme-challenge/GMgoj5xYX7qSIfN9GdmyqHdAHYrCco_Md9kKrT8v0jE",
      "hostname": "mysite.foo.com",
      "port": "80",
      "addressesResolved": [
        "54.85.70.226",
        "52.21.26.68",
        "54.210.179.160",
        "52.1.9.49"
      ],
      "addressUsed": "54.85.70.226",
      "addressesTried": []
    }
  ]
}`
	var c Challenge
	if err := json.Unmarshal([]byte(cJSON), &c); err != nil {
		t.Fatalf("%v", err)
	}
	if g, e := c.Error.Type, "urn:acme:error:caa"; g != e {
		t.Fatalf("%v != %v", g, e)
	}
	if g, e := c.ValidationRecord[0].AddressesResolved[1], net.IPv4(52, 21, 26, 68); !bytes.Equal(g, e) {
		t.Fatalf("%v != %v", g, e)
	}
}
