package gossamer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/GESkunkworks/acfmgr"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws/credentials"
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

// PermCredsConfig holds information about how to obtain session
// credentials from the local client
type PermCredsConfig struct {
	ProfileName string `yaml:"profile_name,omitempty"`
	MFA         *MFA   `yaml:"mfa,omitempty"`
}

func (pcc *PermCredsConfig) validate() (ok bool, err error) {
	//TODO: Add validators
	ok = true
	if pcc.MFA != nil {
		if pcc.MFA.Serial != nil {
			ok, err = pcc.MFA.Serial.validate()
			if !ok {
				return ok, err
			}
		}
		if pcc.MFA.Token != nil {
			ok, err = pcc.MFA.Token.validate()
			if !ok {
				return ok, err
			}
		}
	}
	return ok, err
}

// SAMLConfig holds specific parameters for SAML configuration
type SAMLConfig struct {
	Username                     *CParam `yaml:"username"`
	Password                     *CParam `yaml:"password"`
	URL                          *CParam `yaml:"url"`
	Target                       *CParam `yaml:"target"`
	AllowMappingDurationOverride bool    `yaml:"allow_mapping_duration_override,omitempty"`
}

func (sc *SAMLConfig) validate() (ok bool, err error) {
	//TODO: Add some validation here
	ok = true
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

func (c *CParam) validate() (valid bool, err error) {
	validSources := []string{"config", "env", "prompt"}
	found := false
	for _, val := range validSources {
		if val == c.Source {
			found = true
		}
	}
	valid = found
	if !found {
		msg := fmt.Sprintf("value for source '%s' is invalid must be one of '%s'",
			c.Source, validSources)
		err = errors.New(msg)
	}
	return valid, err

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
			if err != nil {
				return c.result, err
			}
		default:
			c.result, err = getValueFromUser(c.name)
			if err != nil {
				return c.result, err
			}
		}
		c.gathered = true
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
	atype                string
	roleSessionName      string
	parentRegion         string
	allowFailure         bool
	durationSeconds      int64
	parentFlow           *Flow
	parentConfig         *Config
}

func (a *Assumptions) setRelationships(f *Flow, gc *Config) (err error) {
	a.parentFlow = f
	a.parentConfig = gc
	for i := range a.Mappings {
		err = a.Mappings[i].setRelationships(a, f, gc)
		if err != nil {
			return err
		}
	}
	return err
}

func (a *Assumptions) setRoleSessionName(name string) {
	a.roleSessionName = name
}

func (a *Assumptions) getRoleSessionName() *string {
	return (&a.roleSessionName)
}

func (a *Assumptions) assumeMappingsConcurrent() {
	q := make(chan assumptionResult)
	if len(a.Mappings) > 0 {
		goslogger.Loggo.Info("assuming first role to establish initial session")
		go a.Mappings[0].assumeChan(q)
		// wait for the response so we can have a cred for the rest
		result := <-q
		goslogger.Loggo.Info(
			"got result of assumption",
			"message", result.message,
			"error", result.err,
			"profileName", result.profileName,
		)
	}
	if len(a.Mappings) > 1 {
		// now do the rest
		for i := 1; i < len(a.Mappings); i++ {
			go a.Mappings[i].assumeChan(q)
		}
		for i := 1; i < len(a.Mappings); i++ {
			result := <-q
			goslogger.Loggo.Info(
				"got result of assumption",
				"message", result.message,
				"error", result.err,
				"profileName", result.profileName,
			)
		}
	}
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

func (a *Assumptions) getMapping(roleArn string) (ok bool, mappingResult *Mapping) {
	for _, mapping := range a.Mappings {
		if mapping.RoleArn == roleArn {
			mappingResult = &mapping
			ok = true
			return ok, mappingResult
		}
	}
	return ok, mappingResult
}

func (a *Assumptions) setMappingSAMLStuff(roleArn, principalArn string, sc *samlSessionConfig) {
	for i := range a.Mappings {
		if a.Mappings[i].RoleArn == roleArn {
			a.Mappings[i].samlPrincipalArn = principalArn
			a.Mappings[i].parentSAMLConfig = sc
			a.Mappings[i].userDefined = true
		}
	}
}

// getAcfmgrProfileInputs converts mappings into Acfmgr ProfileEntryInput for easy use with AcfMgr package
func (a *Assumptions) getAcfmgrProfileInputs() (pfis []*acfmgr.ProfileEntryInput, err error) {
	countSuccess := 0
	countFail := 0
	total := len(pfis)
	goslogger.Loggo.Debug("entering GetAcfmgrProfileInputs()...")
	for _, mapping := range a.Mappings {
		if !mapping.NoOutput {
			cred, err := mapping.getCredential()
			if err != nil {
				countFail++
			} else {
				profileInput := acfmgr.ProfileEntryInput{
					Credential:       cred,
					ProfileEntryName: mapping.ProfileName,
					Region:           mapping.Region,
					AssumeRoleARN:    mapping.RoleArn,
					Description:      a.parentFlow.Name,
				}
				pfis = append(pfis, &profileInput)
				goslogger.Loggo.Debug("put credential in write queue",
					"RoleArn", mapping.RoleArn,
					"ProfileName", mapping.ProfileName,
					"cred", *profileInput.Credential.AccessKeyId,
				)
				countSuccess++
			}
		} else {
			goslogger.Loggo.Info("Skipping writing cred per configuration directive", "roleArn", mapping.RoleArn)
		}
	}
	if countSuccess < total {
		goslogger.Loggo.Info("failed to obtain some credentials to add to write queue", "total", total, "countFail", countFail, "countSuccess", countSuccess)
	}
	if countSuccess == 0 {
		if !a.allowFailure {
			msg := "failed to queue any desired credentials"
			err = errors.New(msg)
		}
	}
	return pfis, err
}

// MFA holds configuration information for the MFA device
// during a key based auth flow.
type MFA struct {
	Serial *CParam `yaml:"serial"`
	Token  *CParam `yaml:"token"`
}

func (a *Assumptions) setParentRegion(region string) {
	a.parentRegion = region
}

func (a *Assumptions) setDoNotPropagateRegion(dnp bool) {
	a.doNotPropagateRegion = dnp
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
func awsEnvSet() bool {
	commonVars := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_PROFILE",
		"AWS_ROLE_SESSION_NAME",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
	}
	for _, cvar := range commonVars {
		t := os.Getenv(cvar)
		if t != "" {
			return true
		}
	}
	return false
}

// GossFlags holds configuration passed into main via the flag package
// and acts as a temporary structure to hold the variables until they
// can be parsed into a proper Config object. Mostly in place to support
// legacy flags from gossamer 1.x
type GossFlags struct {
	ConfigFile                string
	RolesFile                 string
	OutFile                   string
	RoleArn                   string
	LogFile                   string
	LogLevel                  string
	GeneratedConfigOutputFile string
	DaemonFlag                bool
	Profile                   string
	SerialNumber              string
	TokenCode                 string
	Region                    string
	ProfileEntryName          string
	VersionFlag               bool
	ForceRefresh              bool
	SessionDuration           int64
}

func (gc *Config) setRelationships() (err error) {
	for i := range gc.Flows {
		err = gc.Flows[i].setRelationships(gc)
		if err != nil {
			return err
		}
	}
	return err
}

// Validate checks the config to make sure it is valid
func (gc *Config) Validate() (valid bool, err error) {
	for _, flow := range gc.Flows {
		valid, err = flow.Validate()
	}
	goslogger.Loggo.Debug("finished validating config",
		"valid", valid, "error", err)
	return valid, err

}
