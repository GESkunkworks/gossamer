package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/GESkunkworks/gossamer/gossamer"
)

var version string

func main() {
	// set up flags
	var outFile, roleArn, logFile,
		profile, serialNumber, tokenCode,
		region, loglevel, rolesFile,
		profileEntryName, modeForce string
	var sessionDuration, renewThresholdInt64, secondsInt64 int64
	var versionFlag, daemonFlag, forceRefresh, purgeCredFileFlag bool
	roleSessionName := "gossamer"
	flag.StringVar(&outFile, "o", "./gossamer_creds", "Output credentials file.")
	flag.StringVar(&roleArn, "a", "", "Role ARN to assume.")
	flag.StringVar(&rolesFile, "rolesfile", "", "File that contains json list of roles to assume and add to file.")
	flag.StringVar(&logFile, "logfile", "gossamer.log.json", "JSON logfile location")
	flag.StringVar(&profile, "profile", "", "Cred file profile to use. This overrides the default of using instance role from metadata.")
	flag.StringVar(&serialNumber, "serialnumber", "", "Serial number of MFA device")
	flag.StringVar(&tokenCode, "tokencode", "", "Token code of mfa device.")
	flag.StringVar(&region, "region", "us-east-1", "Region mandatory in mfa and profile mode")
	flag.StringVar(&loglevel, "loglevel", "info", "Log level (info or debug)")
	flag.StringVar(&modeForce, "modeforce", "", "Force a specific mode (e.g., 'mfa_noassume')")
	flag.StringVar(&profileEntryName, "entryname", "gossamer", "when used with single ARN this is the entry name that will be added to the creds file (e.g., '[test-env]')")
	flag.Int64Var(&sessionDuration, "duration", 3600, "Duration of token in seconds. (min=900, max=[read AWS docs]) ")
	flag.Int64Var(&renewThresholdInt64, "t", 10, " threshold in minutes.")
	flag.Int64Var(&secondsInt64, "s", 300, "Duration in seconds to wait between checks.")
	flag.BoolVar(&versionFlag, "v", false, "print version and exit")
	flag.BoolVar(&daemonFlag, "daemon", false, "run as daemon checking every -s duration")
	flag.BoolVar(&forceRefresh, "force", false, "force refresh even if token not yet expired")
	flag.BoolVar(&purgeCredFileFlag, "purgecreds", false, "Purge managed entries from credentials file and exit")
	flag.Parse()
	if versionFlag {
		fmt.Printf("gossamer %s\n", version)
		os.Exit(0)
	}
	// if daemon just log to file
	goslogger.SetLogger(daemonFlag, logFile, loglevel)
	goslogger.Loggo.Info("gossamer: assume-role via instance role", "version", version)
	// exit if no roleArn or file specified
	var accounts []gossamer.Account
	var err error
	if rolesFile != "" {
		accounts, err = gossamer.LoadArnsFile(rolesFile)
		if err != nil {
			panic(err)
		}
	}
	if roleArn == "" && rolesFile == "" && modeForce != "mfa_noassume" {
		goslogger.Loggo.Info("modeForce info", "modeForce", modeForce)
		goslogger.Loggo.Error("must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		os.Exit(0)
	}
	if roleArn != "" && rolesFile == "" {
		// just building one account struct
		acct := gossamer.Account{RoleArn: roleArn, AccountName: profileEntryName, Region: region}
		accounts = append(accounts, acct)
	}
	if modeForce == "mfa_noassume" {
		// just building one account struct
		acct := gossamer.Account{RoleArn: "NA", AccountName: profileEntryName, Region: region}
		accounts = append(accounts, acct)
	}
	if len(accounts) == 0 && modeForce != "mfa_noassume" {
		goslogger.Loggo.Info("modeForce info", "modeForce", modeForce)
		goslogger.Loggo.Error("must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		os.Exit(0)
	}
	if 900 > sessionDuration {
		goslogger.Loggo.Info("sessionDuration is outside threshold (min=900)", "sessionDuration", sessionDuration)
		goslogger.Loggo.Info("exiting...")
		os.Exit(0)
	}
	goslogger.Loggo.Info("OPTIONS", "parsed outfile", outFile)
	goslogger.Loggo.Info("OPTIONS", "parsed arn ", roleArn)
	goslogger.Loggo.Info("OPTIONS", "parsed duration", sessionDuration)
	goslogger.Loggo.Info("OPTIONS", "parsed threshold", renewThresholdInt64)
	goslogger.Loggo.Info("OPTIONS", "parsed between check duration", secondsInt64)
	goslogger.Loggo.Info("OPTIONS", "parsed daemon mode", daemonFlag)
	goslogger.Loggo.Info("OPTIONS", "parsed profile", profile)
	goslogger.Loggo.Info("OPTIONS", "parsed region", region)
	goslogger.Loggo.Info("OPTIONS", "parsed serialNumber", serialNumber)
	goslogger.Loggo.Info("OPTIONS", "parsed tokenCode", tokenCode)
	goslogger.Loggo.Info("OPTIONS", "parsed forceRefresh", forceRefresh)
	goslogger.Loggo.Info("OPTIONS", "parsed modeForce", modeForce)
	// recast some vars for time.Duration use later
	renewThreshold := float64(renewThresholdInt64)
	seconds := float64(secondsInt64)

	opts := gossamer.RunnerOptions{
		OutFile:         outFile,
		Accounts:        accounts,
		RoleSessionName: roleSessionName,
		Profile:         profile,
		SerialNumber:    serialNumber,
		TokenCode:       tokenCode,
		RenewThreshold:  renewThreshold,
		Seconds:         seconds,
		SessionDuration: sessionDuration,
		DaemonFlag:      daemonFlag,
		Mode:            "instance-profile",
		Region:          region,
		Force:           forceRefresh}
	// determine if we're just purging file and exiting
	if purgeCredFileFlag {
		err = gossamer.DeleteCredFileEntries(&opts)
		os.Exit(0)
	}
	// figure out which mode we need to run in
	if modeForce != "" {
		opts.Mode = modeForce
	} else {
		opts.Mode = gossamer.ModeDecider(&opts)
	}
	if opts.Mode == "mfa" || opts.Mode == "mfa_noassume" {
		goslogger.Loggo.Warn("config mismatch, cannot run as daemon in 'mfa*' mode, unsetting daemonFlag")
		opts.DaemonFlag = false
	}
	if opts.DaemonFlag {
		// Go signal notification works by sending `os.Signal`
		// values on a channel. We'll create a channel to
		// receive these notifications (we'll also make one to
		// notify us when the program can exit).
		sigs := make(chan os.Signal, 1)
		done := make(chan bool, 1)
		// `signal.Notify` registers the given channel to
		// receive notifications of the specified signals.
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		// This goroutine executes a blocking receive for
		// signals. When it gets one it'll print it out
		// and then notify the program that it can finish.
		go sigCatcher(sigs, done)
		go runner(&opts)
		goslogger.Loggo.Info("Running and awaiting signal...")
		<-done
		goslogger.Loggo.Info("exiting")
	} else {
		// no daemon, one time run
		runner(&opts)
	}
}

// sigCatcher waits for os signals to terminate gracefully
// after it receives a signal on the sigs channel.
// main() waits for a bool on the done channel.
func sigCatcher(sigs chan os.Signal, done chan bool) {
	sig := <-sigs
	goslogger.Loggo.Info("received signal", "signal", sig)
	done <- true
}

func handleGenErr(err error) {
	if err != nil {
		goslogger.Loggo.Error("Error generating cred", "error", err)
	}
}

// runner, in daemon mode: loops through continuously checking for credential expiration in the creds file
// in standalone mode it just checks once
func runner(opts *gossamer.RunnerOptions) {
	goslogger.Loggo.Debug("entered function", "function", "runner")
	for {
		expired, err := gossamer.ReadExpire(opts.OutFile, opts.RenewThreshold)
		if err != nil {
			panic(err)
		}
		if expired || opts.Force {
			switch opts.Mode {
			case "mfa":
				err = gossamer.GenerateNewMfa(opts, opts.Accounts)
			case "mfa_noassume":
				err = gossamer.GenerateNewMfa(opts, opts.Accounts)
			case "profile-only":
				err = gossamer.GenerateNewProfile(opts, opts.Accounts)
			default:
				for _, acct := range opts.Accounts {
					goslogger.Loggo.Info("Attempting assumption", "ARN", acct.RoleArn)
					err = gossamer.GenerateNewMeta(opts, acct)
					handleGenErr(err)
					time.Sleep(time.Second * time.Duration(1))
				}
			}
			handleGenErr(err)
		} else {
			goslogger.Loggo.Info("Token not yet expired. Exiting with no action.")
		}
		if opts.DaemonFlag {
			duration := time.Second * time.Duration(opts.Seconds)
			goslogger.Loggo.Info("Sleeping", "seconds", duration)
			time.Sleep(duration)
		} else {
			break
		}
	}
}
