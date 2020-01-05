package gossamer

import (
	"errors"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"strings"
)

// assumeRoleWithSession takes an existing session and sets up the assume role inputs for
// the API call
func assumeRoleWithSession(roleArn, roleSessionName *string, duration *int64, sess *session.Session) (*sts.Credentials, error) {
    // set a default in case duration comes in blank
    var blankDuration int64
    if *duration == blankDuration {
        goslogger.Loggo.Debug("detected blank duration, setting to a hard default")
        duration = &[]int64{3600}[0]
    }
	client := sts.New(sess)
    goslogger.Loggo.Debug("preparing assumeRoleWithSession input", "duration", *duration)
	input := sts.AssumeRoleInput{
		RoleArn:         roleArn,
		RoleSessionName: roleSessionName,
		DurationSeconds: duration,
	}
	aso, err := client.AssumeRole(&input)
    if err == nil && *duration > 3600 {
        goslogger.Loggo.Info("Successfully assumed extended session duration.")
    }
    // detect any errors we can handle
    if err != nil && strings.Contains(err.Error(), "DurationSeconds exceeds the MaxSessionDuration") {
        // warn and bump the duration down to default
        goslogger.Loggo.Debug(
            "WARNING: The requested DurationSeconds exceeds the MaxSessionDuration set for this role. Removing duration parameter",
        )
        input := sts.AssumeRoleInput{
            RoleArn:         roleArn,
            RoleSessionName: roleSessionName,
        }
        aso, err = client.AssumeRole(&input)
    }
	return aso.Credentials, err
}

// generateRoleSessionName runs a GetCallerIdentity API call
// to try and auto generate the role session name from an
// established session.
func generateRoleSessionName(sess *session.Session) string {
	client := sts.New(sess)
	callerIdentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "gossamer"
	}
	arnParts := strings.Split(*callerIdentity.Arn, "/")
	return "gossamer-" + arnParts[len(arnParts)-1]
}

// getPermSession looks at the flow's configuration settings and attempts to
// work out how to return the credentials.
func (f *Flow) getPermSession() (sess *session.Session, err error) {
	goslogger.Loggo.Info("getting session from permanent credentials", "flowname", f.Name)
	if f.PermCredsConfig != nil {
		if len(f.PermCredsConfig.ProfileName) > 0 && len(f.Region) > 0 {
			goslogger.Loggo.Debug("using profile for session with specific region", "flowname", f.Name)
			if awsEnvSet() {
				goslogger.Loggo.Info("WARNING: some AWS_* environment variables are set that may interfere with profile session establishment")
			}
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config:  aws.Config{Region: &f.Region},
				Profile: f.PermCredsConfig.ProfileName,
			}))
		} else if len(f.PermCredsConfig.ProfileName) > 0 {
			goslogger.Loggo.Debug("using profile for session", "flowname", f.Name)
			if awsEnvSet() {
				goslogger.Loggo.Info("WARNING: some AWS_* environment variables are set that may interfere with profile session establishment")
			}
			sess, err = session.NewSessionWithOptions(session.Options{
				Profile: f.PermCredsConfig.ProfileName,
			})
			if err != nil {
				return sess, err
			}
		} else {
			// just try default session establish which should use
			// environment variables, instance profile, etc. in the
			// AWS published order. (https://docs.aws.amazon.com/sdk-for-go/api/aws/session/#Session)
			//
			// * Environment Variables
			// * Shared Credentials file
			// * Shared Configuration file (if SharedConfig is enabled)
			// * EC2 Instance Metadata (credentials only)
			goslogger.Loggo.Info("no profile specified so attempting default cred loader from ENV vars, etc", "flowname", f.Name)
			sess, err = session.NewSession()
			if err != nil {
				return sess, err
			}
		}
	}
	if sess == nil {
		err = errors.New("unable to establish initial session")
		return sess, err
	}
	// try to get the role session name from the session we just got
	// because we want the pure name before the MFA session if any
	f.PAss.setRoleSessionName(generateRoleSessionName(sess))
	// now we need to check and see if we need to establish MFA on the session
	goslogger.Loggo.Debug("checking for presence of MFA")
	if f.PermCredsConfig.MFA != nil {
		goslogger.Loggo.Debug("got raw serial and token", "serial", f.PermCredsConfig.MFA.Serial.Value, "token", f.PermCredsConfig.MFA.Token.Value)
		serial, err := f.PermCredsConfig.MFA.Serial.gather()
		if err != nil {
			return sess, err
		}
		token, err := f.PermCredsConfig.MFA.Token.gather()
		if err != nil {
			return sess, err
		}
		goslogger.Loggo.Debug("got gathered serial and token", "serial", serial, "token", token)
		gstInput := &sts.GetSessionTokenInput{
			//TODO: add duration support
			SerialNumber: &serial,
			TokenCode:    &token,
		}
		svcSTS := sts.New(sess)
		gstOutput, err := svcSTS.GetSessionToken(gstInput)
		if err != nil {
			return sess, err
		}
		// build the credentials.cred object manually because the structs are diff.
		statCreds := convertSCredsToCreds(gstOutput.Credentials)
		if len(f.Region) > 0 {
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config: aws.Config{Credentials: statCreds, Region: &f.Region},
			}))
		} else {
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config: aws.Config{Credentials: statCreds},
			}))
		}
	}
	return sess, err
}
