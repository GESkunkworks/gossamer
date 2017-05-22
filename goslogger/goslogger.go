package goslogger

import (
	"os"

	"github.com/inconshreveable/log15"
)

// Loggo is the global logger
var Loggo log15.Logger

// SetLogger sets up logging globally for the packages involved
// in the gossamer runtime.
func SetLogger(daemonFlag bool, logFileS, loglevel string) {
	Loggo = log15.New()
	if daemonFlag {
		Loggo.SetHandler(
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.Must.FileHandler(logFileS, log15.JsonFormat())))
	} else if loglevel == "debug" {
		// log to stdout and file
		Loggo.SetHandler(log15.MultiHandler(
			log15.StreamHandler(os.Stdout, log15.LogfmtFormat()),
			log15.LvlFilterHandler(
				log15.LvlDebug,
				log15.Must.FileHandler(logFileS, log15.JsonFormat()))))
	} else {
		// log to stdout and file
		Loggo.SetHandler(log15.MultiHandler(
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.StreamHandler(os.Stdout, log15.LogfmtFormat())),
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.Must.FileHandler(logFileS, log15.JsonFormat()))))
	}
}
