package gossamer

import (
	"errors"
	"fmt"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"

	"strings"
)

func detectNilStringPointer(label string, pointer *string) (isnil bool, err error) {
	if pointer == nil {
		isnil = true
		msg := fmt.Sprintf("%s is nil", label)
		err = errors.New(msg)
	}
	return isnil, err
}

func detectNilInt64Pointer(label string, pointer *int64) (isnil bool, err error) {
	if pointer == nil {
		isnil = true
		msg := fmt.Sprintf("%s is nil", label)
		err = errors.New(msg)
	}
	return isnil, err
}

func assumeSAMLRoleWithSession(principalArn, roleArn, roleSessionName, assertion *string, duration *int64, client stsiface.STSAPI) (*sts.Credentials, error) {
	var c *sts.Credentials
	if isnil, err := detectNilStringPointer("principalArn", principalArn); isnil {
		return c, err
	}
	if isnil, err := detectNilStringPointer("roleArn", roleArn); isnil {
		return c, err
	}
	if isnil, err := detectNilStringPointer("roleSessionName", roleSessionName); isnil {
		return c, err
	}
	if isnil, err := detectNilStringPointer("assertion", assertion); isnil {
		return c, err
	}
	if isnil, err := detectNilInt64Pointer("duration", duration); isnil {
		return c, err
	}
	goslogger.Loggo.Debug("preparing assumeSAMLRoleWithSession input", "duration", *duration)
	input := sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    principalArn,
		RoleArn:         roleArn,
		SAMLAssertion:   assertion,
		DurationSeconds: duration,
	}
	result, err := client.AssumeRoleWithSAML(&input)
	if err == nil && *duration > 3600 {
		goslogger.Loggo.Debug("Successfully assumed session extended SAML session duration", "duration", *duration)
	}
	if err != nil && detectedDurationProblem(err) {
		goslogger.Loggo.Debug("defaulting to standard duration")
		// warn and bump the duration down to default
		input := sts.AssumeRoleWithSAMLInput{
			PrincipalArn:  principalArn,
			RoleArn:       roleArn,
			SAMLAssertion: assertion,
		}
		result, err = client.AssumeRoleWithSAML(&input)
	}
	if err != nil {
		return c, err
	}
	return result.Credentials, err
}

// assumeRoleWithClient takes an existing session and sets up the assume role inputs for
// the API call
func assumeRoleWithClient(roleArn, roleSessionName *string, duration *int64, client stsiface.STSAPI) (*sts.Credentials, error) {
	var c *sts.Credentials
	if isnil, err := detectNilInt64Pointer("duration", duration); isnil {
		return c, err
	}
	if isnil, err := detectNilStringPointer("roleArn", roleArn); isnil {
		return c, err
	}
	if isnil, err := detectNilStringPointer("roleSessionName", roleSessionName); isnil {
		return c, err
	}
	// set a default in case duration comes in blank
	var blankDuration int64
	if *duration == blankDuration {
		goslogger.Loggo.Debug("detected blank duration, setting to a hard default")
		duration = &[]int64{3600}[0]
	}
	goslogger.Loggo.Debug("preparing assumeRoleWithClient input", "duration", *duration)
	input := sts.AssumeRoleInput{
		RoleArn:         roleArn,
		RoleSessionName: roleSessionName,
		DurationSeconds: duration,
	}
	aso, err := client.AssumeRole(&input)
	if err == nil && *duration > 3600 {
		goslogger.Loggo.Debug("Successfully assumed extended session duration.")
	}
	// detect any errors we can handle
	if err != nil && detectedDurationProblem(err) {
		// warn and bump the duration down to default
		goslogger.Loggo.Debug("defaulting to standard duration")
		input := sts.AssumeRoleInput{
			RoleArn:         roleArn,
			RoleSessionName: roleSessionName,
		}
		aso, err = client.AssumeRole(&input)
	}
	if err != nil {
		return c, err
	}
	return aso.Credentials, err
}

func detectedDurationProblem(err error) bool {
	if err != nil {
		chainingProblem := "DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining"
		configProblem := "DurationSeconds exceeds the MaxSessionDuration"
		if strings.Contains(err.Error(), configProblem) {
			goslogger.Loggo.Debug("WARNING: requested DurationSeconds exceeds the MaxSessionDuration set for this role")
			return true
		} else if strings.Contains(err.Error(), chainingProblem) {
			goslogger.Loggo.Debug("WARNING: The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining.")
			return true
		}
	}
	return false
}

// generateRoleSessionName runs a GetCallerIdentity API call
// to try and auto generate the role session name from a
// established client.
func generateRoleSessionName(client stsiface.STSAPI) string {
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
	if f.sharedSession != nil {
		goslogger.Loggo.Debug("using previously established session for current flow")
		// means we have a session we can already use
		return f.sharedSession, err
	}
	goslogger.Loggo.Debug("no session detected for flow, establishing new")
	if f.PermCredsConfig != nil {
		if len(f.PermCredsConfig.ProfileName) > 0 && len(f.Region) > 0 {
			goslogger.Loggo.Debug("using profile for session with specific region", "flowname", f.Name)
			if awsEnvSet() {
				goslogger.Loggo.Debug("WARNING: some AWS_* environment variables are set that may interfere with profile session establishment")
			}
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config:  aws.Config{Region: &f.Region},
				Profile: f.PermCredsConfig.ProfileName,
			}))
		} else if len(f.PermCredsConfig.ProfileName) > 0 {
			goslogger.Loggo.Debug("using profile for session", "flowname", f.Name)
			if awsEnvSet() {
				goslogger.Loggo.Debug("WARNING: some AWS_* environment variables are set that may interfere with profile session establishment")
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
			goslogger.Loggo.Debug("no profile specified so attempting default cred loader from ENV vars, etc", "flowname", f.Name)
			sess, err = session.NewSession()
			if err != nil {
				return sess, err
			}
		}
	}
	if sess == nil {
		msg := "unable to establish initial session"
		err = errors.New(msg)
		return sess, err
	}
	// try to get the role session name from the session we just got
	// because we want the pure name before the MFA session if any
	stsClient := sts.New(sess)
	f.PAss.setRoleSessionName(generateRoleSessionName(stsClient))
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
	f.sharedSession = sess
	return sess, err
}
