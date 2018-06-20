package storageops

import "github.com/hlandau/acmetool/storage"

// Update targets to remove any mention of hostname from all targets. The
// targets are resaved to disk.
func RemoveTargetHostname(s storage.Store, hostname string) error {
	return s.VisitTargets(func(t *storage.Target) error {
		if !containsName(t.Satisfy.Names, hostname) {
			return nil // continue
		}

		t.Satisfy.Names = removeStringFromList(t.Satisfy.Names, hostname)
		t.Request.Names = removeStringFromList(t.Request.Names, hostname)

		if len(t.Satisfy.Names) == 0 {
			return s.RemoveTarget(t.Filename)
		}

		return s.SaveTarget(t)
	})
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func removeStringFromList(ss []string, s string) []string {
	var r []string
	for _, x := range ss {
		if x != s {
			r = append(r, x)
		}
	}
	return r
}
