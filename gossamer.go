/*
Build aws credentials file with sts assume-role token based on the instance profile.
Specifically designed for an instance profile role to assume-role in another AWS account.

Example:
go run gossamer.go -o ./test.txt -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
*/

package main

import (
    "flag"
    "fmt"
    "text/template"
    "os"
    "time"
    "regexp"
    "strings"
    "bufio"
    "io"
    "os/signal"
    "syscall"
    
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/sts"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/ec2metadata"
    "github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
    "github.com/inconshreveable/log15"
)
// uninitialized version var for -ldflags
var version string
// sample 2017-05-01 23:53:42 +0000 UTC
const dateFormat = "2006-01-02 15:04:05 -0700 MST"
const reDateFormat = `[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} (\-|\+)[0-9]{4} \w{3}`
// what to search for in the creds file to determine expiration
const expiresToken = "# EXPIRES@"
const credFileTemplate = `
####################################################
# DO NOT EDIT
# GOSSAMER MANAGED FILE
# (Will be overwritten regularly)
####################################################
[default]
# ASSUMED ROLE: {{.AssumeRoleARN}}
# ASSUMED FROM INSTANCE ROLE: {{.InstanceRoleARN}}
# GENERATED: {{.Generated}}
{{ .ExpiresToken }}{{.Expiration}}
output = json
region = {{.Region}}
aws_access_key_id = {{.AccessKeyId}}
aws_secret_access_key = {{.SecretAccessKey}}
aws_session_token = {{.SessionToken}}
####################################################
`
// set up logging globally
var logger log15.Logger

// generateNew builds a new aws config file based on the current
// instance profile using the metadata service. It uses assume-role
// and returns an error.
func generateNew(outFile, roleArn, roleSessionName string, sessionDuration int64) (err error){

    // First grab current session to call metadata
    sess := session.Must(session.NewSession())
    meta := ec2metadata.New(sess)
    myRegion, err := meta.Region()
    if err != nil {
        return err
    }
    // get current IAM info for debug
    info, err := meta.IAMInfo()
    instanceProfileArn := info.InstanceProfileArn
    instanceProfileID := info.InstanceProfileID
    logger.Info("Got info from metadata service", 
                "instanceProfileArn",
                instanceProfileArn,
                "instanceProfileID",instanceProfileID)
    // now grab creds from instance profile metadata session
    creds := ec2rolecreds.NewCredentialsWithClient(meta)

    sess_profile := session.Must(session.NewSessionWithOptions(session.Options{
        Config: aws.Config{Credentials: creds},
    }))
    // create new session with current metadata creds
    svc_profile := sts.New(sess_profile)

    // the params we'll need for assume-role
    params := &sts.AssumeRoleInput{
        RoleArn:         &roleArn,
        RoleSessionName: &roleSessionName,
        DurationSeconds: &sessionDuration,
    }
    // now try the assume-role with the new metadata creds
    resp, err := svc_profile.AssumeRole(params)
    if err != nil {
        return err
    }

    // Log the response data. Truncate for security
    logger.Info("Response from AssumeRole", "AccessKeyId", *resp.Credentials.AccessKeyId,
                                             "SecretAccessKey", fmt.Sprintf("%.10s...(redacted)", *resp.Credentials.SecretAccessKey),
                                             "SessionToken", fmt.Sprintf("%.30s...(redacted)", *resp.Credentials.SessionToken),
                                             "Expiration", resp.Credentials.Expiration.String())

    // build a struct for templating aws creds file
    type basicCredential struct {
        AccessKeyId     string
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
        *resp.Credentials.AccessKeyId,
        *resp.Credentials.SecretAccessKey,
        *resp.Credentials.SessionToken,
        resp.Credentials.Expiration.String(),
        time.Now().String(),
        myRegion,
        expiresToken,
        info.InstanceProfileArn,
        roleArn,
        }
    
    // build and write the aws creds file based on the template
    tmpl, err := template.New("test").Parse(credFileTemplate)
    if err != nil { return err }
    f, err := os.Create(outFile)
    if err != nil {
        logger.Crit("Error creating file", "error", err)
        return err
    }
    err = tmpl.Execute(f, baseCreds)
    if err != nil { return err }
    f.Close()
    return err
}

// determineExpired takes a date-time string and parses it then compares
// against the desired renew threshold and returns true if the expiration
// is outside of the threshold. Returns boolean true if need to renew or
// false if no need to renew. 
func determineExpired(dateString string, renewThreshold float64) (bool) {
    timeExpire, err := time.Parse(dateFormat, dateString)
    if err != nil {
        panic(err)
    }
    duration := time.Since(timeExpire)
    logger.Info("Token expiration check", "ExpiresIn", -duration.Minutes(), "renewThreshold", renewThreshold)
    if -duration.Minutes() < renewThreshold {
        return true
    } else {
    return false
    }
}

// createFile creates the file given in 
// inputPath string if it doesn't exist
func createFile(inputPath string) {
	// detect if file exists
	var _, err = os.Stat(inputPath)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(inputPath)
		if err != nil {
            logger.Warn("error creating file", "error", err.Error())
            panic(err)
        }
		defer file.Close()
	}
}

// readExpire reads the passed in aws creds file and looks for a known
// expires token string. If it can't find anything it assumes credentials
// need to be regenerated. If it finds anything it passes the timestamp to 
// determineExpired to see if the token is expired. Returns boolean true
// for expired or false for not expired and an error obj.
func readExpire(outfile string, renewThreshold float64) (expired bool, err error) {
    // compile our dateFormat regex
    filter := regexp.MustCompile(expiresToken + reDateFormat)
    // see if outfile exists and create it if not
    createFile(outfile)
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
            } else {
                return false, err
            }
        }
    }
    return true, err
}

// runner, in daemon mode: loops through continuously checking for credential expiration in the creds file
// in standalone mode it just checks once
func runner(outFile, roleArn, roleSessionName string, renewThreshold, seconds float64, sessionDuration int64, daemonFlag bool) {
    for {
        expired, err := readExpire(outFile, renewThreshold)
        if err != nil {
            panic(err)
        }
        if expired {
            err := generateNew(outFile, roleArn, roleSessionName, sessionDuration)
            if err != nil {
                panic(err)
            }
            logger.Info("Wrote new credentials file.", "path", outFile)
        } else {
            logger.Info("Token not yet expired. Exiting with no action.")
        }
        if daemonFlag {
            time.Sleep(time.Second*time.Duration(seconds))
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
    logger.Info("received signal","signal",sig)
    done <- true
}

func main() {
    // set up flags
    var outFile, roleArn, logFile string
    var sessionDuration, renewThresholdInt64, secondsInt64 int64
    var versionFlag, daemonFlag bool
    roleSessionName := "gossamer"
    flag.StringVar(&outFile, "o", "./gossamer_creds", "Output credentials file.")
    flag.StringVar(&roleArn, "a", "", "Role ARN to assume.")
    flag.StringVar(&logFile, "logfile", "gossamer.log.json", "JSON logfile location")
    flag.Int64Var(&sessionDuration, "duration", 3600, "Duration of token in seconds.")
    flag.Int64Var(&renewThresholdInt64, "t", 10, " threshold in minutes.")
    flag.Int64Var(&secondsInt64, "s", 300, "Duration in seconds to wait between checks.")
    flag.BoolVar(&versionFlag, "v", false, "print version and exit")
    flag.BoolVar(&daemonFlag, "daemon", false, "run as daemon checking every -s duration")
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
    } else {
        // log to stdout and file
        logger.SetHandler(log15.MultiHandler(
            log15.StreamHandler(os.Stdout, log15.LogfmtFormat()),
            log15.LvlFilterHandler(
                log15.LvlInfo,
                log15.Must.FileHandler(logFile, log15.JsonFormat()))))
    }
    logger.Info("gossamer: assume-role via instance role", "version", version)
    // exit if no roleArn specified
    if roleArn == "" {
        logger.Error("must specify role ARN with '-a'. Exiting.")
        os.Exit(0)
    }
    logger.Info("OPTIONS", "parsed outfile", outFile)
    logger.Info("OPTIONS", "parsed arn ", roleArn)
    logger.Info("OPTIONS", "parsed duration", sessionDuration)
    logger.Info("OPTIONS", "parsed threshold", renewThresholdInt64)
    logger.Info("OPTIONS", "parsed between check duration", secondsInt64)
    logger.Info("OPTIONS", "parsed daemon mode", daemonFlag)
    // recast some vars for time.Duration use later
    renewThreshold := float64(renewThresholdInt64)
    seconds := float64(secondsInt64)

    if daemonFlag {
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
        go runner(outFile, roleArn, roleSessionName, renewThreshold, seconds, sessionDuration, daemonFlag)
        logger.Info("Running and awaiting signal...")
        <-done
        logger.Info("exiting")
    } else {
        // no daemon, one time run
        runner(outFile, roleArn, roleSessionName, renewThreshold, seconds, sessionDuration, daemonFlag)
    }
}