package main

import (
    "fmt"
	"os"
    "flag"
    "github.com/GESkunkworks/gossamer/gossamer"
    "github.com/GESkunkworks/gossamer/goslogger"
    "github.com/GESkunkworks/acfmgr"
)

// make the config obj avail to this package globablly
var gc *gossamer.Config

func handle(err error) {
	if err != nil {
	goslogger.Loggo.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

var version string

func main() {
    var gfl gossamer.GossFlags
    flag.StringVar(&gfl.ConfigFile, "c", "", "path to config file that overrides all other parameters")
    flag.StringVar(&gfl.RolesFile, "rolesfile", "", "LEGACY: File that contains json list of roles to assume and add to file.")
    flag.StringVar(&gfl.RoleArn, "a", "", "Role ARN to assume.")
    flag.StringVar(&gfl.OutFile, "o", "./gossamer_creds", "Output credentials file.")
    flag.StringVar(&gfl.LogFile, "logfile", "gossamer.log.json", "JSON logfile location")
    flag.StringVar(&gfl.LogLevel, "loglevel", "info", "Log level (info or debug)")
    flag.StringVar(&gfl.Profile, "profile", "", "Cred file profile to use. This overrides the default of using instance role from metadata.")
    flag.StringVar(&gfl.SerialNumber, "serialnumber", "", "Serial number of MFA device")
    flag.StringVar(&gfl.TokenCode, "tokencode", "", "Token code of mfa device.")
    flag.StringVar(&gfl.Region, "region", "us-east-1", "Region mandatory in mfa and profile mode")
    flag.StringVar(&gfl.ProfileEntryName, "entryname", "gossamer", "when used with single ARN this is the entry name that will be added to the creds file (e.g., '[test-env]')")
    flag.StringVar(&gfl.GeneratedConfigOutputFile, "generate", "", "translates arguments into config file")
    flag.Int64Var(&gfl.SessionDuration, "duration", 3600, "Duration of token in seconds. Duration longer than 3600 seconds only supported by AWS when assuming a single role per tokencode. When assuming multiple roles from rolesfile max duration will always be 3600 as restricted by AWS. (min=900, max=[read AWS docs]) ")
    flag.BoolVar(&gfl.VersionFlag, "v", false, "print version and exit")
    flag.BoolVar(&gfl.ForceRefresh, "force", false, "LEGACY: used to force refresh even if token not yet expired but this field is ignored now")
	//TODO: Add positional args as source type for CParam
    flag.Parse()
    if gfl.VersionFlag {
        fmt.Printf("gossamer %s\n", version)
        os.Exit(0)
    }
    gfl.DaemonFlag = false //TODO: reimplement daemon mode maybe
    goslogger.SetLogger(gfl.DaemonFlag, gfl.LogFile, gfl.LogLevel)
    goslogger.Loggo.Info("Starting gossamer")
	gc = &gossamer.GConf
    var err error
	if gfl.GeneratedConfigOutputFile == "@sample" {
		sampleConfigFilename := "generated-sample-config.yml"
		sampleConfig := gossamer.GenerateConfigSkeleton()
		err = gossamer.WriteConfigToFile(sampleConfig, sampleConfigFilename); handle(err)
		goslogger.Loggo.Info("wrote sample config to file. Exiting", "filename", sampleConfigFilename)
		os.Exit(0)
	}
	if gfl.ConfigFile == "" {
		goslogger.Loggo.Info("no config file provided so attempting to convert legacy arguments into new config format")
		err = gc.ConvertLegacyFlagsToConfig(&gfl); handle(err)
	} else {
		err := gc.ParseConfigFile(gfl.ConfigFile)
		if err != nil {
			fmt.Printf("Error parsing config file: '%s'.  Continuing with parameter defaults\n", err.Error())
		}
	}
    total_count := 0
    // fmt.Println(gc.Dump())
	for _, flow := range(gc.Flows) {
        // call valiate to make sure user didn't put crazy stuff in config
        _, err = flow.Validate(); handle(err)
		// set up session to write to credentials file
        c , err := acfmgr.NewCredFileSession(gc.OutFile); handle(err)
		// regardless of the flow type we'll always run primary
        err = flow.ExecutePrimary(); handle(err)
		// queue entries to write to file
        goslogger.Loggo.Info("queueing primary assumptions to write to file")
        pfisPrimary, err := flow.PAss.GetAcfmgrProfileInputs(); handle(err)
        count := 0
        for _, pfi := range(pfisPrimary) {
            err = c.NewEntry(pfi)
            if err == nil {
                count++
            }
        }
        // now handle SecondaryAssertions (if any)
        if !flow.NoSAss() {
            err = flow.GetSAss(); handle(err)
            goslogger.Loggo.Debug("flow > saml > GetSAss: done")
            goslogger.Loggo.Info("queueing secondary assumptions to write to file")
            pfisSecondary, err := flow.SAss.GetAcfmgrProfileInputs(); handle(err)
            for _, pfi := range(pfisSecondary) {
                err = c.NewEntry(pfi)
                if err == nil {
                    count++
                }
            }
        }

        // write all entries from this flow to file
        err = c.AssertEntries()
        if err != nil {
            goslogger.Loggo.Error("error writing cred entries to file", "err", err)
        }
        total_count = total_count + count
        goslogger.Loggo.Info("Wrote flow entries to file", "count", count, "flow", flow.Name)
	}
    goslogger.Loggo.Info("done", "entries_written", total_count)
}
