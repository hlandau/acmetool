package solver

import "github.com/hlandau/acme/acmeapi"
import "sort"

const NonviableThreshold int32 = -1000000

// Sorter.
type sorter struct {
	authz       *acmeapi.Authorization
	preferencer Preferencer
}

func (s *sorter) Len() int {
	return len(s.authz.Combinations)
}

func (s *sorter) Swap(i, j int) {
	s.authz.Combinations[i], s.authz.Combinations[j] = s.authz.Combinations[j], s.authz.Combinations[i]
}

func (s *sorter) Less(i, j int) bool {
	pi := s.preference(s.authz.Combinations[i]...)
	pj := s.preference(s.authz.Combinations[j]...)
	return pi < pj
}

func (s *sorter) preference(idx ...int) int32 {
	p := int32(0)
	for _, i := range idx {
		if i >= len(s.authz.Challenges) || p <= NonviableThreshold {
			return NonviableThreshold
		}

		v := s.preferencer.Preference(s.authz.Challenges[i])
		p = satAdd(p, v)
	}
	return p
}

func satAdd(x, y int32) int32 {
	v := int64(x) + int64(y)
	if v > int64(-NonviableThreshold) {
		return -NonviableThreshold
	}

	if v < int64(NonviableThreshold) {
		return NonviableThreshold
	}

	return int32(v)
}

// TypePreferencer returns a preference according to the type of the challenge.
//
// Unknown challenge types are nonviable.
type TypePreferencer map[string]int32

func (p TypePreferencer) Preference(ch *acmeapi.Challenge) int32 {
	v, ok := p[ch.Type]
	if !ok {
		return NonviableThreshold
	}
	return v
}

func (p TypePreferencer) Copy() TypePreferencer {
	tp := TypePreferencer{}
	for k, v := range p {
		tp[k] = v
	}
	return tp
}

// PreferFast prefers fast types.
var PreferFast = TypePreferencer{
	"tls-sni-01": 1,
	"http-01":    0,
	"dns-01":     -100,

	// Avoid unless necessary. In future we might want to determine whether we
	// have a key and prefer this accordingly.
	"proofOfPossession:": -40,
}

// Determines the degree to which a challenge is preferred. Higher values are
// more preferred.
type Preferencer interface {
	Preference(ch *acmeapi.Challenge) int32
}

// Sort authorization combinations by preference. Crops Combinations to viable
// combinations.
func SortCombinations(authz *acmeapi.Authorization, preferencer Preferencer) {
	s := sorter{
		authz:       authz,
		preferencer: preferencer,
	}
	sort.Stable(sort.Reverse(&s))

	for i := range authz.Combinations {
		pi := s.preference(authz.Combinations[i]...)
		if pi <= NonviableThreshold {
			authz.Combinations = authz.Combinations[0:i]
			return
		}
	}
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
