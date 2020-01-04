package gossamer

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/GESkunkworks/acfmgr"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

// GConf holds config and exports for use in other
// packages
var GConf Config

// Config is an internal struct for storing
// configuration needed to run this application
type Config struct {
	OutFile string  `yaml:"output_file"`
	Flows   []*Flow `yaml:"flows"`
}
// Flow describes an authentication flow and can
// be one of many types. It contains the user's
// desired auth flow behavior via keys or saml.
type Flow struct {
	Name       string       `yaml:"name"`
	SAMLConfig *SAMLConfig  `yaml:"saml_config,omitempty"`
    PermCredsConfig *PermCredsConfig `yaml:"permanent,omitempty"`
	PAss       *Assumptions `yaml:"primary_assumptions,omitempty"`
	SAss       *Assumptions `yaml:"secondary_assumptions,omitempty"`
	Region     string       `yaml:"region,omitempty"`
    AllowFailure bool       `yaml:"allow_failure"`
	credsType       string
	roleSessionName      string
	// Key type properties
	DoNotPropagateRegion bool `yaml:"do_not_propagate_region"`
}

// PermCredsConfig holds information about how to obtain session
// credentials from the local client
type PermCredsConfig struct {
    ProfileName          string     `yaml:"profile_name,omitempty"`
	MFA                  *MFA       `yaml:"mfa,omitempty"`
}

func (pcc *PermCredsConfig) validate() (ok bool, err error) {
    //TODO: Add validators
    return ok, err
}

// SAMLConfig holds specific parameters for SAML configuration
type SAMLConfig struct {
	Username *CParam `yaml:"username"`
	Password *CParam `yaml:"password"`
	URL      *CParam `yaml:"url"`
	Target   *CParam `yaml:"target"`
	//TODO: support Duration
}

func (sc *SAMLConfig) validate() (ok bool, err error) {
    //TODO: Add some validation here
    return ok, err
}

// CParam provides a way to identify sources for config parameters
// that are more robust that simple key value. For example you can
// say that a configuration parameter is sourced from an environment
// variable or from a prompt in addition to just raw value.
// It has a gather() method which is used to retrieve its value.
type CParam struct {
	name   string
	Source string `yaml:"source"`
	Value  string `yaml:"value,omitempty"`
	// unexported fields
	gathered   bool
	result     string
	parentflow string
}

// gather looks at the source of the config parameter
// and attempts to retrieve the value using that method.
// It returns the value as a string and any errors.
func (c *CParam) gather() (val string, err error) {
	// if we've already grabbed it in the past
	// we'll just return it again
	if c.gathered {
		return c.result, err
	}
	// otherwise we'll collect
	switch c.Source {
	case "config":
		switch c.name {
		case "Password":
			msg := fmt.Sprintf("%s %s",
				"this program does not support putting password in plaintext in config file",
				"please switch config parameter for password to 'env' or 'prompt'",
			)
			err = errors.New(msg)
			return val, err
		}
		c.gathered = true
		c.result = c.Value
		return c.Value, err
	case "env":
		c.result = os.Getenv(c.Value)
		if len(c.result) < 1 {
			message := fmt.Sprintf("env var '%s' specified for param is empty", c.Value)
			err = errors.New(message)
		}
		c.gathered = true
		return c.result, err
	case "prompt":
		fmt.Printf("gathering value for flow '%s': ", c.parentflow)
		switch c.name {
		case "Password":
			c.result, err = getSecretFromUser(c.name)
		default:
			c.result, err = getValueFromUser(c.name)
		}
		return c.result, err
	}
	// default to sending blank and an error if it got here
	message := fmt.Sprintf("config parameter '%s' unknown", c.Source)
	err = errors.New(message)
	val = ""
	return val, err
}

// Assumptions holds the configuration for the roles that
// will be assumed using both the primary and secondary credentials
// Primary:
// In the case of SAML that's the roles in the assertion.
// In the case of key and key-mfa it's the roles that will be assumed directly
// Secondary:
// Secondary assumptions' mappings rely on sponsor credentials
// that are presumed to be obtained from primary mappings
type Assumptions struct {
	AllRoles             bool      `yaml:"all_roles"`
	Mappings             []Mapping `yaml:"mappings"`
	doNotPropagateRegion bool
	roleSessionName      string
	parentRegion         string
	parentFlow           string
    allowFailure         bool
}

func (ap *Assumptions) setRoleSessionName(name string) {
	ap.roleSessionName = name
}

func (a *Assumptions) getRoleSessionName() *string {
	return (&a.roleSessionName)
}

// convertSCredstoCreds converts credentials from the sts to the credentials package
// per the specifications of the golan AWS SDK
func convertSCredsToCreds(screds *sts.Credentials) (creds *credentials.Credentials) {
	creds = credentials.NewStaticCredentials(
		*screds.AccessKeyId,
		*screds.SecretAccessKey,
		*screds.SessionToken)
	return creds
}

// NoSAss returns false if the flow has any secondary assumptions defined
// and true if not.
func (f *Flow) NoSAss() bool {
	if f.SAss != nil {
		return false
	}
	return true
}

// Mapping holds the configuration for role assumptions
// and their desired profile name to be written to the
// credentials file after they've been assumed.
type Mapping struct {
	RoleArn         string `yaml:"role_arn"`
	ProfileName     string `yaml:"profile_name,omitempty"`
	Region          string `yaml:"region,omitempty"`
	NoOutput        bool   `yaml:"no_output,omitempty"`
	SponsorCredsArn string `yaml:"sponsor_creds_arn,omitempty"`
	credential      *sts.Credentials
	//TODO: support Duration
}

func (m *Mapping) getCredential() (cred *sts.Credentials, err error) {
	if m.credential == nil {
		msg := fmt.Sprintf("credential is nil for %s", m.RoleArn)
		err = errors.New(msg)
	}
	cred = m.credential
	return cred, err

}

func (a *Assumptions) getMappingCredential(roleArn string) (cred *sts.Credentials, err error) {
	found := false
	for _, mapping := range a.Mappings {
		if mapping.RoleArn == roleArn {
			found = true
			cred, err = mapping.getCredential()
		}
	}
	if !found {
		msg := fmt.Sprintf("credentials not found for %s", roleArn)
		err = errors.New(msg)
	}
	return cred, err
}

// func (m *Mapping) setCredential(cred *sts.Credentials) (err error) {
//     if cred == nil {
//         msg := fmt.Sprintf("incoming credential is nil")
//         err = errors.New(msg)
//     }
//     m.credential = cred
//     return err
//
// }

// validate checks for common things that always need to be done
// to mappings before they can be written out
func (m *Mapping) validate(strict bool) (err error) {
	if len(m.ProfileName) < 1 {
		goslogger.Loggo.Debug("detected missing profile name", "roleArn", m.RoleArn)
		uid, err := getRoleUniqueId(m.RoleArn)
		if err != nil {
			return err
		}
		m.ProfileName = *uid
		goslogger.Loggo.Debug("set profilename", "profileName", m.ProfileName)
	}
	if strict {
		_, err = m.getCredential()
	}
	return err
}

func (m *Mapping) setRegionIfNotSet(region string) {
	if len(m.Region) < 1 {
		m.Region = region
	}
}

// validateMappings checks all mappings within a set of
// assumptions to make sure it has common things set
func (a *Assumptions) validateMappings(strict bool) (err error) {
	goslogger.Loggo.Debug("validating mappings in assumptions",
		"numMappings", len(a.Mappings),
		"parentFlow", a.parentFlow,
	)
	for i := range a.Mappings {
		err = a.Mappings[i].validate(strict)
		if err != nil {
			return err
		}
	}
	if !a.doNotPropagateRegion && len(a.parentRegion) > 0 {
		goslogger.Loggo.Info("propagating region from flow to assumption mappings", "parentFlow", a.parentFlow)
		for i := range a.Mappings {
			a.Mappings[i].setRegionIfNotSet(a.parentRegion)
		}
	} else {
		goslogger.Loggo.Debug("not setting parentRegion on assumptions",
			"parentFlow", a.parentFlow,
			"a.doNotPropagateRegion", a.doNotPropagateRegion,
			"len(parentRegion)", len(a.parentRegion),
		)
	}
	return err
}

// dump spits back some basic info about the mapping
// useful during debugging
func (m *Mapping) dump() string {
	return fmt.Sprintf("RoleArn: %s\nProfileName: %s\ncredential: %s\n", m.RoleArn, m.ProfileName, *m.credential.AccessKeyId)
}

func (m *Assumptions) getMapping(roleArn string) (ok bool, mappingResult *Mapping) {
	for _, mapping := range m.Mappings {
		if mapping.RoleArn == roleArn {
			mappingResult = &mapping
			ok = true
			return ok, mappingResult
		}
	}
	return ok, mappingResult
}

func (m *Assumptions) setMappingCredential(roleArn string, cred *sts.Credentials) (ok bool) {
	for i := range m.Mappings {
		if m.Mappings[i].RoleArn == roleArn {
			m.Mappings[i].credential = cred
			return ok
		}
	}
	return ok
}

func (m *Assumptions) setMappingProfileName(roleArn, name string) (ok bool) {
	for i := range m.Mappings {
		if m.Mappings[i].RoleArn == roleArn {
			m.Mappings[i].ProfileName = name
			return ok
		}
	}
	return ok
}

// buildMappings builds []*Mappings slice for the session when the mappings are not known
// ahead of time and can't be parsed from the config file. This will generally come in as
// the result of a SAML Assertion where a bunch of roles come in and we want to try and
// map them to a profile name or region based on their ARN. This mapping is defined in the
// config file so we do the conversion here.
func (m *Assumptions) buildMappings(mappings []*Mapping) (err error) {
	for _, wmapping := range mappings {
		ok, mapping := m.getMapping(wmapping.RoleArn)
		if ok {
			goslogger.Loggo.Debug("buildMappings: found mapping", "mapping", mapping.RoleArn)
			// means we know about the role already and just need the creds
			// and maybe the profile name if we don't have one.
			if len(mapping.ProfileName) < 1 {
				m.setMappingProfileName(mapping.RoleArn, wmapping.ProfileName)
			}
			m.setMappingCredential(mapping.RoleArn, wmapping.credential)
		}
		if !ok && m.AllRoles {
			if !ok {
				// means its totally new to us so we just take whatever we get
				goslogger.Loggo.Debug("buildMappings: new mapping", "mapping", wmapping.RoleArn)
				newMapping := Mapping{
					RoleArn:     wmapping.RoleArn,
					ProfileName: wmapping.ProfileName,
					credential:  wmapping.credential,
				}
				m.Mappings = append(m.Mappings, newMapping)
			}
		}
	}
	return err
}

// GetAcfmgrProfileInputs converts mappings into Acfmgr ProfileEntryInput for easy use with AcfMgr package
func (a *Assumptions) GetAcfmgrProfileInputs() (pfis []*acfmgr.ProfileEntryInput, err error) {
	count_success := 0
	count_fail := 0
	total := len(pfis)
	goslogger.Loggo.Debug("entering GetAcfmgrProfileInputs()...")
	for _, mapping := range a.Mappings {
		if !mapping.NoOutput {
			cred, err := mapping.getCredential()
			if err != nil {
				goslogger.Loggo.Error("error retrieiving credential", "error", err)
				count_fail++
			} else {
				profileInput := acfmgr.ProfileEntryInput{
					Credential:       cred,
					ProfileEntryName: mapping.ProfileName,
					Region:           mapping.Region,
					AssumeRoleARN:    mapping.RoleArn,
                    Description:      a.parentFlow,
				}
				pfis = append(pfis, &profileInput)
				goslogger.Loggo.Debug("put credential in write queue",
                    "RoleArn", mapping.RoleArn,
                    "ProfileName", mapping.ProfileName,
                    "cred", *profileInput.Credential.AccessKeyId,
                )
				count_success++
			}
		} else {
			goslogger.Loggo.Info("Skipping writing cred per configuration directive", "roleArn", mapping.RoleArn)
		}
	}
	if count_success < total {
		goslogger.Loggo.Info("failed to obtain some credentials to add to write queue", "total", total, "count_fail", count_fail, "count_success", count_success)
	}
	if count_success == 0 {
        if !a.allowFailure {
            msg := fmt.Sprintf("failed to queue any desired credentials")
            err = errors.New(msg)
        }
	}
	return pfis, err
}

// getListOfArns gets a list of the role arns in the mappings and returns it
func (m *Assumptions) getListOfArns() (roles []string) {
    for _, mapping := range(m.Mappings) {
        roles = append(roles, mapping.RoleArn)
    }
    return roles
}

// MFA holds configuration information for the MFA device
// during a key based auth flow.
type MFA struct {
	Serial *CParam `yaml:"serial"`
	Token  *CParam `yaml:"token"`
}

// KeySource holds the configuration information for
// where they key credentials are located. Options are
// profile or default. "profile" will pull from the desired profile
// in the credentials file. "default" will follow the
// standard credentials search order as defined by AWS.
// KeySource will be used during the flow's GetSession()
// method to provide  a session.
type KeySource struct {
	SourceType  string `yaml:"source_type"`
	ProfileName string `yaml:"profile_name"`
}

func (a *Assumptions) setParentRegion(region string) {
	a.parentRegion = region
}

func (a *Assumptions) setDoNotPropagateRegion(dnp bool) {
	a.doNotPropagateRegion = dnp
}

// Validate checks for valid properties and returns
// true if no problems are detected and false with an
// error message if there are issues
func (f *Flow) Validate() (valid bool, err error) {
    // first detect type
    switch {
    case f.SAMLConfig != nil && f.PermCredsConfig == nil:
        f.credsType = "saml"
        valid, err = f.SAMLConfig.validate()
        if err != nil {return valid, err}
    case f.SAMLConfig == nil && f.PermCredsConfig != nil:
        f.credsType = "permanent"
        valid, err = f.PermCredsConfig.validate()
        if err != nil {return valid, err}
    default:
        err = errors.New("only one type of creds can be used for starting each flow please choose one of: permanent or saml")
        return valid, err
    }
    goslogger.Loggo.Info("detected type for flow", "flowName", f.Name, "type", f.credsType)
	if len(f.Region) > 1 {
		goslogger.Loggo.Info("flow: detected user specified region so validating it")
		var validRegion = regexp.MustCompile(`\w{2}-([a-z]*-){1,2}\d{1}`)
		if validRegion.MatchString(f.Region) {
			valid = true
		} else {
			err = errors.New("region must match '\\w{2}-([a-z]*-){1,2}\\d{1}'")
			return valid, err
		}
	}
	// set parentRegion and inheritance setting on assumptions if set on flow
	if f.PAss != nil {
		f.PAss.parentFlow = f.Name
		if !f.DoNotPropagateRegion && len(f.Region) > 0 {
			goslogger.Loggo.Info("setting parent region on primary assumptions", "flow", f.Name)
			f.PAss.setParentRegion(f.Region)
		} else {
			f.PAss.setDoNotPropagateRegion(true)
		}
        if f.AllowFailure {
            f.PAss.allowFailure = true
        }
	}
	if f.SAss != nil {
		f.SAss.parentFlow = f.Name
		if !f.DoNotPropagateRegion && len(f.Region) > 0 {
			goslogger.Loggo.Info("setting parent region on secondary assumptions", "flow", f.Name)
			f.SAss.setParentRegion(f.Region)
		} else {
			f.SAss.setDoNotPropagateRegion(true)
		}
        if f.AllowFailure {
            f.SAss.allowFailure = true
        }
	}
	return valid, err
}

// ParseConfigFile takes a yaml filename as input and
// attempts to parse it into a config object.
func (gc *Config) ParseConfigFile(filename string) (err error) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, gc)
	// add labels to CParams so we can sanely prompt for them
	for _, flow := range gc.Flows {
		if flow.SAMLConfig != nil {
			flow.SAMLConfig.Username.name = "Username"
			flow.SAMLConfig.Username.parentflow = flow.Name

			flow.SAMLConfig.Password.name = "Password"
			flow.SAMLConfig.Password.parentflow = flow.Name

			flow.SAMLConfig.URL.name = "URL"
			flow.SAMLConfig.URL.parentflow = flow.Name

			flow.SAMLConfig.Target.name = "Target"
			flow.SAMLConfig.Target.parentflow = flow.Name
		}
		if flow.PermCredsConfig != nil {
			if flow.PermCredsConfig.MFA != nil {
				flow.PermCredsConfig.MFA.Serial.name = "Serial"
				flow.PermCredsConfig.MFA.Serial.parentflow = flow.Name

				flow.PermCredsConfig.MFA.Token.name = "Token"
				flow.PermCredsConfig.MFA.Token.parentflow = flow.Name
			}
		}
	}
	return err
}

// Dump returns a string of the full parsed configuration
func (gc *Config) Dump() string {
	var r []byte
	r, _ = yaml.Marshal(gc)
	return string(r)
}

// getSecretFromUser grabs input from user for single string
// thanks to stackoverflow poster gihanchanuka
// https://stackoverflow.com/questions/2137357/getpasswd-functionality-in-go
func getSecretFromUser(label string) (valueHidden string, err error) {
	fmt.Printf("Enter value for '%s' (hidden): ", label)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return valueHidden, err
	}
	valueHidden = strings.TrimSpace(string(bytePassword))
	return valueHidden, err
}

// getValueFromUser grabs input from user for single string
// thanks to stackoverflow poster gihanchanuka
// https://stackoverflow.com/questions/2137357/getpasswd-functionality-in-go
func getValueFromUser(label string) (value string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter value for '%s': ", label)

	value, err = reader.ReadString('\n')
	if err != nil {
		return value, err
	}
	value = strings.TrimSpace(value)
	return value, err
}

// awsEnvSet returns true if any of the common AWS_* environment variables are set
func awsEnvSet() (bool) {
    commonVars := []string{
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_ROLE_SESSION_NAME",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    }
    for _, cvar := range(commonVars) {
        t := os.Getenv(cvar)
        if t != "" {
            return true
        }
    }
    return false
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
            if err != nil { return sess, err }
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
        if err != nil {return sess, err}
        token, err := f.PermCredsConfig.MFA.Token.gather()
        if err != nil {return sess, err}
        goslogger.Loggo.Debug("got gathered serial and token", "serial", serial, "token", token)
		gstInput := &sts.GetSessionTokenInput{
			//TODO: add duration support
            SerialNumber:    &serial,
            TokenCode:       &token,
        }
		svcSTS := sts.New(sess)
        gstOutput, err := svcSTS.GetSessionToken(gstInput)
        if err != nil { return sess, err }
        // build the credentials.cred object manually because the structs are diff.
		statCreds := convertSCredsToCreds(gstOutput.Credentials)
		if len(f.Region) > 0 {
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config: aws.Config{Credentials: statCreds, Region: &f.Region},
			}))
		} else {
			sess = session.Must(session.NewSessionWithOptions(session.Options{
				Config: aws.Config{Credentials: statCreds,},
			}))
		}
    }
	return sess, err
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

// validate checks for valid properties and returns
// true if no problems are detected and false with an
// error message if there are issues
func (k *KeySource) validate() (valid bool, err error) {
	if k.SourceType == "default" || k.SourceType == "profile" {
		valid = true
	} else {
		err = errors.New("key source source type must be of one 'profile' or 'default'")
		return valid, err
	}
	if k.SourceType == "profile" {
		if len(k.ProfileName) < 1 {
			err = errors.New("when using key source type 'profile' must specify profile_name")
			return valid, err
		}
	}
	return valid, err
}

// assumeRoleWithSession takes an existing session and sets up the assume role inputs for
// the API call
func assumeRoleWithSession(roleArn, roleSessionName *string, sess *session.Session) (*sts.Credentials, error) {
	client := sts.New(sess)
	input := sts.AssumeRoleInput{
		RoleArn:         roleArn,
		RoleSessionName: roleSessionName,
		//TODO: Add duration
	}
	aso, err := client.AssumeRole(&input)
	return aso.Credentials, err
}

type GossFlags struct {
    ConfigFile string
    RolesFile string
    OutFile string
    RoleArn string
    LogFile string
    LogLevel string
    GeneratedConfigOutputFile string
    DaemonFlag bool
    Profile string
    SerialNumber string
    TokenCode string
    Region string
    ProfileEntryName string
    SessionDuration int64
	VersionFlag bool
    ForceRefresh bool
}

