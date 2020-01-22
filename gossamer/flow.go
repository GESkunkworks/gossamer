package gossamer

import (
	"errors"
	"github.com/GESkunkworks/acfmgr"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws/session"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"regexp"
)

// Validate checks for valid properties and returns
// true if no problems are detected and false with an
// error message if there are issues
func (f *Flow) Validate() (valid bool, err error) {
	// first detect type
	switch {
	case f.SAMLConfig != nil && f.PermCredsConfig == nil:
		f.credsType = "saml"
		valid, err = f.SAMLConfig.validate()
		if !valid {
			goslogger.Loggo.Debug("got invalid samlconfig")
		}
		if err != nil {
			return valid, err
		}
	case f.SAMLConfig == nil && f.PermCredsConfig != nil:
		f.credsType = "permanent"
		valid, err = f.PermCredsConfig.validate()
		if !valid {
			goslogger.Loggo.Debug("got invalid permcredsconfig")
		}
		if err != nil {
			return valid, err
		}
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
	// set a default session duration if none is specified
	var blankDuration int64
	if f.DurationSeconds == blankDuration {
		f.DurationSeconds = []int64{3600}[0]
	}
	// set parentRegion and inheritance setting on assumptions if set on flow
	if f.PAss != nil {
		f.PAss.atype = "primary"
		goslogger.Loggo.Debug("setting primary assumption duration", "duration", f.DurationSeconds)
		f.PAss.durationSeconds = f.DurationSeconds
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
		f.SAss.atype = "secondary"
		goslogger.Loggo.Debug("setting secondary assumption duration", "duration", f.DurationSeconds)
		f.SAss.durationSeconds = f.DurationSeconds
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
    if f.PAss == nil && f.SAss == nil {
        err = errors.New(
            "please specify primary or secondary assumption criteria")
        valid = false
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
	if err != nil {
		return err
	}
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
	err = gc.setRelationships()
	return err
}

// GetAcfmgrProfileInputs converts all flow's mappings into Acfmgr ProfileEntryInput for easy use with AcfMgr package
func (f *Flow) GetAcfmgrProfileInputs() (pfis []*acfmgr.ProfileEntryInput, err error) {
	primary, err := f.PAss.getAcfmgrProfileInputs()
	if err != nil {
		return pfis, err
	}
	pfis = append(pfis, primary...)
	if !f.NoSAss() {
		secondary, err := f.SAss.getAcfmgrProfileInputs()
		if err != nil {
			return pfis, err
		}
		pfis = append(pfis, secondary...)
		return pfis, err
	}
	return pfis, err
}

func (f *Flow) setRelationships(gc *Config) (err error) {
	f.parentConfig = gc
	if f.PAss != nil {
		err = f.PAss.setRelationships(f, gc)
		if err != nil {
			return err
		}
	}
	if f.SAss != nil {
		err = f.SAss.setRelationships(f, gc)
		if err != nil {
			return err
		}
	}
	return err
}

// Flow describes an authentication flow and can
// be one of many types. It contains the user's
// desired auth flow behavior via keys or saml.
type Flow struct {
	Name                 string           `yaml:"name"`
	SAMLConfig           *SAMLConfig      `yaml:"saml_config,omitempty"`
	PermCredsConfig      *PermCredsConfig `yaml:"permanent,omitempty"`
	PAss                 *Assumptions     `yaml:"primary_assumptions,omitempty"`
	SAss                 *Assumptions     `yaml:"secondary_assumptions,omitempty"`
	DurationSeconds      int64            `yaml:"session_duration_seconds,omitempty"`
	Region               string           `yaml:"region,omitempty"`
	DoNotPropagateRegion bool             `yaml:"do_not_propagate_region"`
	AllowFailure         bool             `yaml:"allow_failure"`
	credsType            string
	parentConfig         *Config
	sharedSession        *session.Session
}

// NoSAss returns false if the flow has any secondary assumptions defined
// and true if not.
func (f *Flow) NoSAss() bool {
	return f.SAss == nil
}
