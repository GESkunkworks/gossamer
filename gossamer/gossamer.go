package gossamer

/*
Build aws credentials file with sts assume-role token based on the instance profile or assume role from a list of accounts with an MFA token.

Specifically designed for an instance profile role to assume-role in another AWS account.

Example:
go run gossamer.go -o ./test.txt -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
*/

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"../acfmgr"
	"../goslogger"
)

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

func haveCredsWillWrite(creds *sts.Credentials, opts *RunnerOptions, instanceProfileArn string, acctCurrent Account) (err error) {
	goslogger.Loggo.Debug("entered function", "function", "haveCredsWillWrite")
	// if instance-profile then we'll just look in the meta for the region
	// and overwrite the default or what the user put in
	if opts.Mode == "instance-profile" {
		var errr error
		opts.Region, errr = getRegion()
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
		Region:          opts.Region,
		ExpiresToken:    expiresToken,
		InstanceRoleARN: instanceProfileArn,
		AssumeRoleARN:   acctCurrent.RoleArn,
	}
	// build and write the aws creds file based on the template
	tmpl, err := template.New("test").Parse(credFileTemplate)
	if err != nil {
		return err
	}
	goslogger.Loggo.Debug("About to write creds file")
	// make a buffer to hold templated string
	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, baseCreds)
	// build the acfmgr cred file session
	credContents := strings.Split(buf.String(), "\n")
	c, err := acfmgr.NewCredFileSession(opts.OutFile)
	credName := "[" + acctCurrent.AccountName + "]"
	c.NewEntry(credName, credContents)
	err = c.AssertEntries()
	goslogger.Loggo.Info("Wrote new credentials file.", "path", opts.OutFile)
	if err != nil {
		return err
	}
	return err
}

func assumer(profile *sts.STS, opts *RunnerOptions, acct Account) error {

	// the params we'll need for assume-role with mfa
	params := &sts.AssumeRoleInput{
		RoleArn:         &acct.RoleArn,
		RoleSessionName: &opts.RoleSessionName,
		DurationSeconds: &opts.SessionDuration,
	}
	// now try the assume-role with the loaded creds
	resp, errr := profile.AssumeRole(params)
	if errr != nil {
		return errr
	}

	// Log the response data. Truncate for security
	goslogger.Loggo.Info("Response from AssumeRole", "AccessKeyId", *resp.Credentials.AccessKeyId,
		"AccountName", fmt.Sprintf("%s", acct.AccountName),
		"RoleArn", fmt.Sprintf("%s", acct.RoleArn),
		"Expiration", resp.Credentials.Expiration.String())

	instanceProfileArn := "NA"
	errr = haveCredsWillWrite(resp.Credentials, opts, instanceProfileArn, acct)
	return errr
}

// determineExpired takes a date-time string and parses it then compares
// against the desired renew threshold and returns true if the expiration
// is outside of the threshold. Returns boolean true if need to renew or
// false if no need to renew.
func determineExpired(dateString string, renewThreshold float64) bool {
	goslogger.Loggo.Debug("entered function", "function", "determineExpired")
	timeExpire, err := time.Parse(dateFormat, dateString)
	if err != nil {
		panic(err)
	}
	duration := time.Since(timeExpire)
	goslogger.Loggo.Info("Token expiration check", "ExpiresIn", -duration.Minutes(), "renewThreshold", renewThreshold)
	if -duration.Minutes() < renewThreshold {
		return true
	}
	return false
}

// configuration holds a list of
// account structs
type configuration struct {
	Roles []Account
}

func getRegion() (mr string, errrr error) {
	goslogger.Loggo.Debug("entered function", "function", "getRegion")
	// First grab current session to call metadata
	sess := session.Must(session.NewSession())
	meta := ec2metadata.New(sess)
	mr, errrr = meta.Region()
	if errrr != nil {
		return mr, errrr
	}
	return mr, errrr
}

// GenerateNewProfile modifies an aws config file based on the desired
// profile. It uses assume-role and returns an error.
func GenerateNewProfile(opts *RunnerOptions, accounts []Account) (err error) {
	goslogger.Loggo.Debug("entered function", "function", "generateNewProfile")
	// now grab creds from profile file
	creds := credentials.NewSharedCredentials(opts.OutFile, opts.Profile)
	cval, errrr := creds.Get()
	if errrr != nil {
		return errrr
	}
	goslogger.Loggo.Debug("iamcreds", "creds", cval)

	sessProfile := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds},
	}))
	svcProfile := sts.New(sessProfile)

	for _, acct := range accounts {
		goslogger.Loggo.Debug("working on account",
			"AccountName", acct.AccountName,
			"RoleArn", acct.RoleArn)
		err = assumer(svcProfile, opts, acct)
		if err != nil {
			return err
		}
	}
	goslogger.Loggo.Info("GenerateNewProfile wrote credentials", "numberOfCredentialsWritten", len(accounts))
	return err
}

// GenerateNewMfa modifies an aws config file based on the desired
// profile and provided mfa code. It uses assume-role and returns an error.
func GenerateNewMfa(opts *RunnerOptions, accounts []Account) (err error) {
	goslogger.Loggo.Debug("entered function", "function", "generateNewMfa")
	// now grab creds from profile file
	creds := credentials.NewSharedCredentials(opts.OutFile, opts.Profile)
	cval, errrr := creds.Get()
	if errrr != nil {
		return errrr
	}
	goslogger.Loggo.Debug("iamcreds", "creds", cval)

	sessProfile := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Credentials: creds},
	}))
	svcProfile := sts.New(sessProfile)

	gstInput := &sts.GetSessionTokenInput{
		DurationSeconds: &opts.SessionDuration,
		SerialNumber:    &opts.SerialNumber,
		TokenCode:       &opts.TokenCode,
	}

	gstOutput, err := svcProfile.GetSessionToken(gstInput)
	// goslogger.Loggo.Debug("Get session token result...", "gstOutput.Credentials", gstOutput.Credentials)
	if err != nil {
		goslogger.Loggo.Crit("Error in getSessionToken", "error", err)
		return err
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
		goslogger.Loggo.Info("working on account",
			"AccountName", acct.AccountName,
			"RoleArn", acct.RoleArn)
		if opts.Mode == "mfa" {
			err = assumer(svcMfa, opts, acct)
		} else if opts.Mode == "mfa_noassume" {
			err = haveCredsWillWrite(gstOutput.Credentials, opts, "NA", acct)
		}
		if err != nil {
			handleGenErr(err)
		}
	}
	goslogger.Loggo.Info("GenerateNewMfa wrote credentials", "numberOfCredentialsWritten", len(accounts))
	return err
}

func handleGenErr(err error) {
	if err != nil {
		goslogger.Loggo.Error("Error generating cred", "error", err)
	}
}

// GenerateNewMeta builds a credentials type from instance metadata
// for use in generateNew
func GenerateNewMeta(opts *RunnerOptions, acctCurrent Account) (errr error) {
	goslogger.Loggo.Debug("entered function", "function", "generatedNewMeta")
	// First grab current session to call metadata
	sess := session.Must(session.NewSession())
	meta := ec2metadata.New(sess)
	// get current IAM info for debug
	info, errr := meta.IAMInfo()
	instanceProfileArn := info.InstanceProfileArn
	instanceProfileID := info.InstanceProfileID
	goslogger.Loggo.Info("Got info from metadata service",
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
		RoleSessionName: &opts.RoleSessionName,
		DurationSeconds: &opts.SessionDuration,
	}
	// now try the assume-role with the new metadata creds
	resp, errr := svcProfile.AssumeRole(params)
	if errr != nil {
		return errr
	}

	// Log the response data. Truncate for security
	goslogger.Loggo.Info("Response from AssumeRole", "AccessKeyId", *resp.Credentials.AccessKeyId,
		"AccountName", fmt.Sprintf("%s", acctCurrent.AccountName),
		"RoleArn", fmt.Sprintf("%s", acctCurrent.RoleArn),
		"Expiration", resp.Credentials.Expiration.String())
	errr = haveCredsWillWrite(resp.Credentials, opts, instanceProfileArn, acctCurrent)
	return errr
}

func createFile(filename string) error {
	_, err := os.Create(filename)
	if err != nil {
		return err
	}
	return err
}

// ReadExpire reads the passed in aws creds file and looks for a known
// expires token string. If it can't find anything it assumes credentials
// need to be regenerated. If it finds anything it passes the timestamp to
// determineExpired to see if the token is expired. Returns boolean true
// for expired or false for not expired and an error obj.
func ReadExpire(outfile string, renewThreshold float64) (expired bool, err error) {
	goslogger.Loggo.Debug("entered function", "function", "readExpire")
	// compile our dateFormat regex
	filter := regexp.MustCompile(expiresToken + reDateFormat)
	// see if outfile exists and exit func if not
	fi, err := os.Open(outfile)
	if err != nil {
		err = createFile(outfile)
		return true, err
	}
	// close fi on exit and check for its returned error
	defer func() {
		if err := fi.Close(); err != nil {
			goslogger.Loggo.Warn(fmt.Sprintf("Error reading existing creds file, assumption is to create new: %s", err))
		}
	}()
	// make a read buffer
	r := io.Reader(fi)
	if err != nil {
		return true, err
	}
	input := bufio.NewScanner(r)
	goslogger.Loggo.Info("Scanning credentials file...")
	for input.Scan() {
		line := input.Text()
		match := filter.FindAllString(line, -1)
		if match != nil {
			dateString := strings.Split(match[0], "@")[1]
			goslogger.Loggo.Info("Detected expiration string", "TokenExpires", dateString)
			expired := determineExpired(dateString, renewThreshold)
			if expired {
				return true, err
			}
			return false, err
		}
	}
	return true, err
}

// ModeDecider looks at the given input parameters and tries to decide
// the user's intention. Right now this is just deciding between
// using MFA or using instance-profile.
func ModeDecider(opts *RunnerOptions) (mode string) {
	goslogger.Loggo.Debug("entered function", "function", "modeDecider")
	var reModeMfa = regexp.MustCompile(`[0-9]{6}`)
	var reModeProfile = regexp.MustCompile(`\w{1,}`)
	goslogger.Loggo.Debug("modeDecider", "reModeMfa match?", reModeMfa.MatchString(opts.TokenCode))
	goslogger.Loggo.Debug("modeDecider", "reModeProfile match?", reModeProfile.MatchString(opts.Profile))
	// determine which mode we're going to run in
	mode = "instance-profile"
	switch {
	case reModeMfa.MatchString(opts.TokenCode) && reModeProfile.MatchString(opts.Profile):
		mode = "mfa"
	case reModeProfile.MatchString(opts.Profile) && opts.SerialNumber == "" && opts.TokenCode == "":
		mode = "profile-only"
	default:
		mode = "instance-profile"
	}
	goslogger.Loggo.Info("MODE", "determined mode", mode)
	return mode
}

// Account just holds the rolearn, region, and
// account name for each entry to build from
type Account struct {
	RoleArn     string
	AccountName string
	Region      string
	RoundRobin  bool
}

// RunnerOptions type provides easier arguments to the runner function
type RunnerOptions struct {
	OutFile, RoleSessionName, Mode, Profile, SerialNumber, TokenCode, Region string
	RenewThreshold, Seconds                                                  float64
	SessionDuration                                                          int64
	DaemonFlag, Force                                                        bool
	Accounts                                                                 []Account
}

// DeleteCredFileEntries deletes all credentials
// loaded in to RunnerOptions.[]Account in the
// creds file.
func DeleteCredFileEntries(opts *RunnerOptions) error {
	// build the acfmgr cred file session
	credContents := []string{"blank"}
	c, err := acfmgr.NewCredFileSession(opts.OutFile)
	for _, acct := range opts.Accounts {
		credName := "[" + acct.AccountName + "]"
		goslogger.Loggo.Debug("purgecreds", "addingEntry", credName)
		c.NewEntry(credName, credContents)
	}
	err = c.DeleteEntries()
	if err != nil {
		return err
	}
	return err
}

// LoadArnsFile just returns a []string from a json
// config file
func LoadArnsFile(filename string) ([]Account, error) {
	var rlist []Account
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
