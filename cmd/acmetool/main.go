package main

import "gopkg.in/alecthomas/kingpin.v2"
import "github.com/hlandau/acme/storage"
import "github.com/hlandau/acme/interaction"
import "github.com/hlandau/xlog"
import "github.com/hlandau/degoutils/xlogconfig"
import "gopkg.in/hlandau/easyconfig.v1/manual"

var log, Log = xlog.New("acmetool")

var (
	stateFlag = kingpin.Flag("state", "Path to the state directory (env: ACME_STATE_DIR)").
			Default(storage.RecommendedPath).
			Envar("ACME_STATE_DIR").
			PlaceHolder(storage.RecommendedPath).
			String()

	logLevelFlag = kingpin.Flag("loglevel", "Logging level").
			Default("NOTICE").
			String()

	batchFlag = kingpin.Flag("batch", "Do not attempt interaction; useful for cron jobs").
			Bool()

	reconcileCmd = kingpin.Command("reconcile", "Reconcile ACME state").Default()

	wantCmd = kingpin.Command("want", "Add a target with one or more hostnames").
		Arg("hostname", "hostnames for which a certificate is desired").Required().Strings()
)

func main() {
	cmd := kingpin.Parse()

	err := manual.Set("xlog.severity", *logLevelFlag)
	log.Fatale(err, "log level")
	xlogconfig.Init()

	if *batchFlag {
		interaction.NonInteractive = true
	}

	switch cmd {
	case "reconcile":
		reconcile()
	case "want":
		want()
		reconcile()
	}
}

func reconcile() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	err = s.Reconcile()
	log.Fatale(err, "reconcile")
}

func want() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	tgt := storage.Target{
		Names: *wantCmd,
	}

	err = s.AddTarget(tgt)
	log.Fatale(err, "add target")
}
