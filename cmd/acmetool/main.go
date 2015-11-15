package main

import "gopkg.in/alecthomas/kingpin.v2"
import "github.com/hlandau/acme/storage"
import "github.com/hlandau/xlog"

var log, Log = xlog.New("acmetool")

var (
	stateFlag = kingpin.Flag("state", "Path to the state directory (env: ACMETOOL_STATE_PATH)").
			Default(storage.RecommendedPath).
			Envar("ACMETOOL_STATE_PATH").
			PlaceHolder(storage.RecommendedPath).
			String()

	reconcileCmd = kingpin.Command("reconcile", "Reconcile ACME state").Default()
)

func main() {
	cmd := kingpin.Parse()

	switch cmd {
	case "reconcile":
		s, err := storage.New(*stateFlag)
		log.Fatale(err, "storage")

		err = s.Reconcile()
		log.Fatale(err, "reconcile")
	}
}
