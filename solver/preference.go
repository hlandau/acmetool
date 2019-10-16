package solver

import (
	"gopkg.in/hlandau/acmeapi.v2"
	"sort"
)

// Any challenge having a preference at or below this value will never be used.
const NonviableThreshold int32 = -1000000

type sorter struct {
	authz       *acmeapi.Authorization
	order       []int
	preferencer Preferencer
}

func (s *sorter) Len() int {
	return len(s.order)
}

func (s *sorter) Swap(i, j int) {
	s.order[i], s.order[j] = s.order[j], s.order[i]
}

func (s *sorter) Less(i, j int) bool {
	pi := s.preference(&s.authz.Challenges[i])
	pj := s.preference(&s.authz.Challenges[j])
	return pi < pj
}

func (s *sorter) preference(ch *acmeapi.Challenge) int32 {
	v := s.preferencer.Preference(ch)
	if v <= NonviableThreshold {
		return NonviableThreshold
	}

	return v
}

// Returns a list of indices to authz.Challenges, sorted by preference, most
// preferred first.
func SortChallenges(authz *acmeapi.Authorization, preferencer Preferencer) (preferenceOrder []int) {
	preferenceOrder = make([]int, len(authz.Challenges))
	for i := 0; i < len(authz.Challenges); i++ {
		preferenceOrder[i] = i
	}

	s := sorter{
		authz:       authz,
		order:       preferenceOrder,
		preferencer: preferencer,
	}
	sort.Stable(sort.Reverse(&s))
	return
}

// TypePreferencer returns a preference according to the type of the challenge.
//
// Unknown challenge types are nonviable.
type TypePreferencer map[string]int32

// Implements Preferencer.
func (p TypePreferencer) Preference(ch *acmeapi.Challenge) int32 {
	v, ok := p[ch.Type]
	if !ok {
		return NonviableThreshold
	}
	return v
}

// Returns a copy of TypePreferencer, so that it can be mutated without
// changing the original.
func (p TypePreferencer) Copy() TypePreferencer {
	tp := TypePreferencer{}
	for k, v := range p {
		tp[k] = v
	}
	return tp
}

// PreferFast prefers fast types.
var PreferFast = TypePreferencer{
	"tls-sni-02": 2,
	"tls-sni-01": 1,
	"http-01":    0,

	// Disable DNS challenges for now. They're practically unusable and the Let's
	// Encrypt live server doesn't support them at this time anyway.
	"dns-01": -10,
}

// Determines the degree to which a challenge is preferred. Higher values are
// more preferred. Any value <= NonviableThreshold will never be used.
type Preferencer interface {
	// Get the preference for the given challenge.
	Preference(ch *acmeapi.Challenge) int32
}
