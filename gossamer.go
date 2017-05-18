/*
Build aws credentials file with sts assume-role token based on the instance profile.
Specifically designed for an instance profile role to assume-role in another AWS account.

Example:
go run gossamer.go -o ./test.txt -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
*/

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/inconshreveable/log15"

	"./acfmgr"
)

// uninitialized version var for -ldflags
var version string

// sample 2017-05-01 23:53:42 +0000 UTC
const dateFormat = "2006-01-02 15:04:05 -0700 MST"
const reDateFormat = `[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} (\-|\+)[0-9]{4} \w{3}`

// what to search for in the creds file to determine expiration
const expiresToken = "# EXPIRES@"
const credFileTemplate = `# DO NOT EDIT
# GOSSAMER MANAGED SECTION
# (Will be overwritten regularly)
####################################################
# ASSUMED ROLE: {{.AssumeRoleARN}}
# ASSUMED FROM INSTANCE ROLE: {{.InstanceRoleARN}}
# GENERATED: {{.Generated}}
{{ .ExpiresToken }}{{.Expiration}}
output = json
region = {{.Region}}
aws_access_key_id = {{.AccessKeyID}}
aws_secret_access_key = {{.SecretAccessKey}}
aws_session_token = {{.SessionToken}}
`

// set up logging globally
var logger log15.Logger

func haveCredsWillWrite(creds *sts.Credentials, opts *runnerOptions, instanceProfileArn string, acctCurrent account) (err error) {
	logger.Debug("entered function", "function", "haveCredsWillWrite")
	// if instance-profile then we'll just look in the meta for the region
	// and overwrite the default or what the user put in
	if opts.mode == "instance-profile" {
		var errr error
		opts.region, errr = getRegion()
		if errr != nil {
			return errr
		}
	}
	// build a struct for templating aws creds file
	type basicCredential struct {
		AccessKeyID     string
		SecretAccessKey string
		SessionToken    string
		Expiration      string
		Generated       string
		Region          string
		ExpiresToken    string
		InstanceRoleARN string
		AssumeRoleARN   string
	}

	// assign values to struct
	baseCreds := basicCredential{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
		Expiration:      creds.Expiration.String(),
		Generated:       time.Now().String(),
		Region:          opts.region,
		ExpiresToken:    expiresToken,
		InstanceRoleARN: instanceProfileArn,
		AssumeRoleARN:   acctCurrent.RoleArn,
	}
	// build and write the aws creds file based on the template
	tmpl, err := template.New("test").Parse(credFileTemplate)
	if err != nil {
		return err
	}
	logger.Debug("About to write creds file")
	// make a buffer to hold templated string
	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, baseCreds)
	// build the acfmgr cred file session
	credContents := strings.Split(buf.String(), "\n")
	c, err := acfmgr.NewCredFileSession(opts.outFile)
	credName := "[" + acctCurrent.AccountName + "]"
	c.NewEntry(credName, credContents)
	err = c.AssertEntries()
	if err != nil {
		return err
	}
	return err
}

func assumer(profile *sts.STS, opts *runnerOptions, acct account) error {

	// the params we'll need for assume-role with mfa
	params := &sts.AssumeRoleInput{
		RoleArn:         &acct.RoleArn,
		RoleSessionName: &opts.roleSessionName,
		DurationSeconds: &opts.sessionDuration,
	}
	// now try the assume-role with the loaded creds
	resp, errr := profile.AssumeRole(params)
	if errr != nil {
		return errr
	}

	// Log the response data. Truncate for security
	logger.Info("Response from AssumeRole", "AccessKeyId", *resp.Credentials.AccessKeyId,
		"SecretAccessKey", fmt.Sprintf("%.10s...(redacted)", *resp.Credentials.SecretAccessKey),
		"SessionToken", fmt.Sprintf("%.30s...(redacted)", *resp.Credentials.SessionToken),
		"Expiration", resp.Credentials.Expiration.String())

	instanceProfileArn := "NA"
	errr = haveCredsWillWrite(resp.Credentials, opts, instanceProfileArn, acct)
	return errr
}

// generateNewMfa builds a new aws config file based on the desired
// profile and provided mfa code. It uses assume-role and returns an error.
func generateNewMfa(opts *runnerOptions, accounts []account) (err error) {
	logger.Debug("entered function", "function", "generateNewMfa")
	// now grab creds from profile file
	creds := credentials.NewSharedCredentials(opts.outFile, opts.profile)
	cval, errrr := creds.Get()
	if errrr != nil {
		return errrr
	}
	logger.Debug("iamcreds", "creds", cval)

	sessProfile := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds},
	}))
	svcProfile := sts.New(sessProfile)

	gstInput := &sts.GetSessionTokenInput{
		DurationSeconds: &opts.sessionDuration,
		SerialNumber:    &opts.serialNumber,
		TokenCode:       &opts.tokenCode,
	}

	gstOutput, err := svcProfile.GetSessionToken(gstInput)
	if err != nil {
		logger.Crit("Error in getSessionToken", "error", err)
		os.Exit(1)
	}
	// build the credentials.cred object manually because the structs are diff.
	statCreds := credentials.NewStaticCredentials(
		*gstOutput.Credentials.AccessKeyId,
		*gstOutput.Credentials.SecretAccessKey,
		*gstOutput.Credentials.SessionToken)
	sessMfa := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: statCreds},
	}))
	// now using the new session we can open another sts session
	svcMfa := sts.New(sessMfa)

	for _, acct := range accounts {
		logger.Debug("working on account",
			"AccountName", acct.AccountName,
			"RoleArn", acct.RoleArn)
		err = assumer(svcMfa, opts, acct)
		if err != nil {
			return err
		}
	}
	logger.Info("wrote credentials", "numberOfCredentialsWritten", len(accounts))
	return err
}

// generateNewMeta builds a credentials type from instance metadata
// for use in generateNew
func generateNewMeta(opts *runnerOptions, acctCurrent account) (errr error) {
	logger.Debug("entered function", "function", "generatedNewMeta")
	// First grab current session to call metadata
	sess := session.Must(session.NewSession())
	meta := ec2metadata.New(sess)
	// get current IAM info for debug
	info, errr := meta.IAMInfo()
	instanceProfileArn := info.InstanceProfileArn
	instanceProfileID := info.InstanceProfileID
	logger.Info("Got info from metadata service",
		"instanceProfileArn",
		instanceProfileArn,
		"instanceProfileID", instanceProfileID)
	// now grab creds from instance profile metadata session
	creds := ec2rolecreds.NewCredentialsWithClient(meta)

	sessProfile := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds},
	}))
	// create new session with current metadata creds
	svcProfile := sts.New(sessProfile)

	// the params we'll need for assume-role
	params := &sts.AssumeRoleInput{
		RoleArn:         &acctCurrent.RoleArn,
		RoleSessionName: &opts.roleSessionName,
		DurationSeconds: &opts.sessionDuration,
	}
	// now try the assume-role with the new metadata creds
	resp, errr := svcProfile.AssumeRole(params)
	if errr != nil {
		return errr
	}

	// Log the response data. Truncate for security
	logger.Info("Response from AssumeRole", "AccessKeyId", *resp.Credentials.AccessKeyId,
		"SecretAccessKey", fmt.Sprintf("%.10s...(redacted)", *resp.Credentials.SecretAccessKey),
		"SessionToken", fmt.Sprintf("%.30s...(redacted)", *resp.Credentials.SessionToken),
		"Expiration", resp.Credentials.Expiration.String())
	errr = haveCredsWillWrite(resp.Credentials, opts, instanceProfileArn, acctCurrent)
	return errr
}

// determineExpired takes a date-time string and parses it then compares
// against the desired renew threshold and returns true if the expiration
// is outside of the threshold. Returns boolean true if need to renew or
// false if no need to renew.
func determineExpired(dateString string, renewThreshold float64) bool {
	logger.Debug("entered function", "function", "determineExpired")
	timeExpire, err := time.Parse(dateFormat, dateString)
	if err != nil {
		panic(err)
	}
	duration := time.Since(timeExpire)
	logger.Info("Token expiration check", "ExpiresIn", -duration.Minutes(), "renewThreshold", renewThreshold)
	if -duration.Minutes() < renewThreshold {
		return true
	}
	return false
}

// readExpire reads the passed in aws creds file and looks for a known
// expires token string. If it can't find anything it assumes credentials
// need to be regenerated. If it finds anything it passes the timestamp to
// determineExpired to see if the token is expired. Returns boolean true
// for expired or false for not expired and an error obj.
func readExpire(outfile string, renewThreshold float64) (expired bool, err error) {
	logger.Debug("entered function", "function", "readExpire")
	// compile our dateFormat regex
	filter := regexp.MustCompile(expiresToken + reDateFormat)
	// see if outfile exists and exit func if not
	fi, err := os.Open(outfile)
	if err != nil {
		return true, err
	}
	// close fi on exit and check for its returned error
	defer func() {
		if err := fi.Close(); err != nil {
			logger.Warn(fmt.Sprintf("Error reading existing creds file, assumption is to create new: %s", err))
		}
	}()
	// make a read buffer
	r := io.Reader(fi)
	if err != nil {
		return true, err
	}
	input := bufio.NewScanner(r)
	logger.Info("Scanning credentials file...")
	for input.Scan() {
		line := input.Text()
		match := filter.FindAllString(line, -1)
		if match != nil {
			dateString := strings.Split(match[0], "@")[1]
			logger.Info("Detected expiration string", "TokenExpires", dateString)
			expired := determineExpired(dateString, renewThreshold)
			if expired {
				return true, err
			}
			return false, err
		}
	}
	return true, err
}

// runnerOptions type provides easier arguments to the runner function
type runnerOptions struct {
	outFile, roleSessionName, mode, profile, serialNumber, tokenCode, region string
	renewThreshold, seconds                                                  float64
	sessionDuration                                                          int64
	daemonFlag, force                                                        bool
	accounts                                                                 []account
}

// modeDecider looks at the given input parameters and tries to decide
// the user's intention. Right now this is just deciding between
// using MFA or using instance-profile.
func modeDecider(opts *runnerOptions) (mode string) {
	logger.Debug("entered function", "function", "modeDecider")
	var reModeMfa = regexp.MustCompile(`[0-9]{6}`)
	var reModeProfile = regexp.MustCompile(`\w*`)
	reSerialString := `(\w.*:\w.*:\w.*::\d.*:mfa.*)|(\w{4}\d{8})`
	var reModeSerial = regexp.MustCompile(reSerialString)
	logger.Debug("modeDecider", "reModeMfa match?", reModeMfa.MatchString(opts.tokenCode))
	logger.Debug("modeDecider", "reModeProfile match?", reModeProfile.MatchString(opts.profile))
	logger.Debug("modeDecider", "reModeSerial match?", reModeSerial.MatchString(opts.serialNumber))
	// determine which mode we're going to run in
	mode = "instance-profile"
	switch {
	case reModeMfa.MatchString(opts.tokenCode) && reModeProfile.MatchString(opts.profile) && reModeSerial.MatchString(opts.serialNumber):
		mode = "mfa"
	case opts.tokenCode == "" && opts.serialNumber == "" && reModeProfile.MatchString(opts.profile):
		mode = "profile-only"
	default:
		mode = "instance-profile"
	}
	if opts.serialNumber != "" && mode != "mfa" {
		logger.Warn("Mode uncertainty", "detected non-null value for serial", opts.serialNumber, "but did not match regex", reSerialString)
	}
	logger.Info("MODE", "determined mode", mode)
	return mode
}

// runner, in daemon mode: loops through continuously checking for credential expiration in the creds file
// in standalone mode it just checks once
func runner(opts *runnerOptions) {
	logger.Debug("entered function", "function", "runner")
	for {
		expired, err := readExpire(opts.outFile, opts.renewThreshold)
		if err != nil {
			panic(err)
		}
		if expired || opts.force {
			switch opts.mode {
			case "mfa":
				err = generateNewMfa(opts, opts.accounts)
			default:
				for _, acct := range opts.accounts {
					err = generateNewMeta(opts, acct)
				}
			}
			if err != nil {
				panic(err)
			}
			logger.Info("Wrote new credentials file.", "path", opts.outFile)
		} else {
			logger.Info("Token not yet expired. Exiting with no action.")
		}
		if opts.daemonFlag {
			time.Sleep(time.Second * time.Duration(opts.seconds))
		} else {
			break
		}
	}
}

// sigCatcher waits for os signals to terminate gracefully
// after it receives a signal on the sigs channel.
// main() waits for a bool on the done channel.
func sigCatcher(sigs chan os.Signal, done chan bool) {
	sig := <-sigs
	logger.Info("received signal", "signal", sig)
	done <- true
}

// account just holds the rolearn
// and account name for each entry to build from
type account struct {
	RoleArn     string
	AccountName string
}

// configuration holds a list of
// account structs
type configuration struct {
	Roles []account
}

// loadArnsFile just returns a []string from a json
// config file
func loadArnsFile(filename string) ([]account, error) {
	var rlist []account
	file, err := os.Open(filename)
	if err != nil {
		return rlist, err
	}
	decoder := json.NewDecoder(file)
	config := configuration{}
	err = decoder.Decode(&config)
	if err != nil {
		return rlist, err
	}
	return config.Roles, err
}

func deleteCredFileEntries(opts *runnerOptions) error {
	// build the acfmgr cred file session
	credContents := []string{"blank"}
	c, err := acfmgr.NewCredFileSession(opts.outFile)
	for _, acct := range opts.accounts {
		credName := "[" + acct.AccountName + "]"
		logger.Debug("purgecreds", "addingEntry", credName)
		c.NewEntry(credName, credContents)
	}
	err = c.DeleteEntries()
	if err != nil {
		return err
	}
	return err
}

func main() {
	// set up flags
	var outFile, roleArn, logFile, profile, serialNumber, tokenCode, region, loglevel, rolesFile, profileEntryName string
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
	flag.StringVar(&profileEntryName, "entryname", "gossamer", "when used with single ARN this is the entry name that will be added to the creds file (e.g., '[test-env]')")
	flag.Int64Var(&sessionDuration, "duration", 3600, "Duration of token in seconds. (min=900, max=3600) ")
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
	logger = log15.New()
	// if daemon just log to file
	if daemonFlag {
		logger.SetHandler(
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.Must.FileHandler(logFile, log15.JsonFormat())))
	} else if loglevel == "debug" {
		// log to stdout and file
		logger.SetHandler(log15.MultiHandler(
			log15.StreamHandler(os.Stdout, log15.LogfmtFormat()),
			log15.LvlFilterHandler(
				log15.LvlDebug,
				log15.Must.FileHandler(logFile, log15.JsonFormat()))))
	} else {
		// log to stdout and file
		logger.SetHandler(log15.MultiHandler(
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.StreamHandler(os.Stdout, log15.LogfmtFormat())),
			log15.LvlFilterHandler(
				log15.LvlInfo,
				log15.Must.FileHandler(logFile, log15.JsonFormat()))))
	}
	logger.Info("gossamer: assume-role via instance role", "version", version)
	// exit if no roleArn or file specified
	var accounts []account
	var err error
	if rolesFile != "" {
		accounts, err = loadArnsFile(rolesFile)
		if err != nil {
			panic(err)
		}
	}
	if roleArn == "" && rolesFile == "" {
		logger.Error("must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		os.Exit(0)
	}
	if roleArn != "" && rolesFile == "" {
		// just building one account struct
		acct := account{RoleArn: roleArn, AccountName: profileEntryName}
		accounts = append(accounts, acct)
	}
	if len(accounts) == 0 {
		logger.Error("must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		os.Exit(0)
	}
	if (900 > sessionDuration) || (sessionDuration > 3600) {
		logger.Info("sessionDuration is outside threshold (min=900, max=3600)", "sessionDuration", sessionDuration)
		logger.Info("exiting...")
		os.Exit(0)
	}
	logger.Info("OPTIONS", "parsed outfile", outFile)
	logger.Info("OPTIONS", "parsed arn ", roleArn)
	logger.Info("OPTIONS", "parsed duration", sessionDuration)
	logger.Info("OPTIONS", "parsed threshold", renewThresholdInt64)
	logger.Info("OPTIONS", "parsed between check duration", secondsInt64)
	logger.Info("OPTIONS", "parsed daemon mode", daemonFlag)
	logger.Info("OPTIONS", "parsed profile", profile)
	logger.Info("OPTIONS", "parsed region", region)
	logger.Info("OPTIONS", "parsed serialNumber", serialNumber)
	logger.Info("OPTIONS", "parsed tokenCode", tokenCode)
	logger.Info("OPTIONS", "parsed forceRefresh", forceRefresh)
	// recast some vars for time.Duration use later
	renewThreshold := float64(renewThresholdInt64)
	seconds := float64(secondsInt64)

	opts := runnerOptions{
		outFile:         outFile,
		accounts:        accounts,
		roleSessionName: roleSessionName,
		profile:         profile,
		serialNumber:    serialNumber,
		tokenCode:       tokenCode,
		renewThreshold:  renewThreshold,
		seconds:         seconds,
		sessionDuration: sessionDuration,
		daemonFlag:      daemonFlag,
		mode:            "instance-profile",
		region:          region,
		force:           forceRefresh}
	// determine if we're just purging file and exiting
	if purgeCredFileFlag {
		err = deleteCredFileEntries(&opts)
		os.Exit(0)
	}
	// figure out which mode we need to run in
	opts.mode = modeDecider(&opts)
	if opts.mode == "mfa" {
		logger.Warn("config mismatch, cannot run as daemon in 'mfa' mode, unsetting daemonFlag")
		opts.daemonFlag = false
	}
	if opts.daemonFlag {
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
		logger.Info("Running and awaiting signal...")
		<-done
		logger.Info("exiting")
	} else {
		// no daemon, one time run
		runner(&opts)
	}
}

func getRegion() (mr string, errrr error) {
	logger.Debug("entered function", "function", "getRegion")
	// First grab current session to call metadata
	sess := session.Must(session.NewSession())
	meta := ec2metadata.New(sess)
	mr, errrr = meta.Region()
	if errrr != nil {
		return mr, errrr
	}
	return mr, errrr
}
