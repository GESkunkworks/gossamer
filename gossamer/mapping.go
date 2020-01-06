package gossamer

import (
	"errors"
	"fmt"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

func newSAMLMapping(roleArn, principalArn string, sc *samlSessionConfig) *Mapping {
	var m Mapping
	m.RoleArn = roleArn
	m.parentSAMLConfig = sc
	m.samlPrincipalArn = principalArn
	return &m
}

// Mapping holds the configuration for role assumptions
// and their desired profile name to be written to the
// credentials file after they've been assumed.
type Mapping struct {
	RoleArn           string `yaml:"role_arn"`
	ProfileName       string `yaml:"profile_name,omitempty"`
	Region            string `yaml:"region,omitempty"`
	NoOutput          bool   `yaml:"no_output,omitempty"`
	SponsorCredsArn   string `yaml:"sponsor_creds_arn,omitempty"`
	credential        *sts.Credentials
	DurationSeconds   int64 `yaml:"session_duration_seconds,omitempty"`
	parentAssumptions *Assumptions
	parentFlow        *Flow
	parentConfig      *Config
	parentSAMLConfig  *samlSessionConfig
	samlPrincipalArn  string
	userDefined       bool
}

func (m *Mapping) setRelationships(a *Assumptions, f *Flow, gc *Config) (err error) {
	m.parentAssumptions = a
	m.parentFlow = f
	m.parentConfig = gc
	return err
}

func (m *Mapping) getCredential() (cred *sts.Credentials, err error) {
	if m.credential == nil {
		msg := fmt.Sprintf("credential is nil for %s", m.RoleArn)
		err = errors.New(msg)
	}
	cred = m.credential
	return cred, err

}

// validate checks for common things that always need to be done
// to mappings before they can be written out
func (m *Mapping) validate() (err error) {
	var blankDuration int64
	// if m.parentAssumptions.durationSeconds == nil {
	// 	m.parentAssumptions.durationSeconds = blankDuration
	// }
	// if m.parentFlow.DurationSeconds == nil {
	// 	m.parentFlow.DurationSeconds = blankDuration
	// }
	if m.DurationSeconds == blankDuration {
		// grab from parents or set default
		if m.parentAssumptions.durationSeconds == blankDuration {
			if m.parentFlow.DurationSeconds == blankDuration {
				// default
				m.DurationSeconds = []int64{3600}[0]
			} else {
				// get from Flow
				m.DurationSeconds = m.parentFlow.DurationSeconds
			}
		} else {
			// get from parent Assumptions
			m.DurationSeconds = m.parentAssumptions.durationSeconds
		}
	}
	// samlSessionDuration overrides all of the above
	if m.parentSAMLConfig != nil {
		m.DurationSeconds = m.parentSAMLConfig.getSessionDuration()
		if m.DurationSeconds == 0 {
			// default
			m.DurationSeconds = []int64{3600}[0]
		}
	}
	if len(m.ProfileName) < 1 {
		goslogger.Loggo.Debug("detected missing profile name", "roleArn", m.RoleArn)
		uid, err := getRoleUniqueID(m.RoleArn)
		if err != nil {
			return err
		}
		m.ProfileName = *uid
		goslogger.Loggo.Debug("set profilename", "profileName", m.ProfileName)
	}
	if !m.parentAssumptions.doNotPropagateRegion {
		m.setRegionIfNotSet(m.parentAssumptions.parentRegion)
	}
	return err
}

func (m *Mapping) setRegionIfNotSet(region string) {
	if len(m.Region) < 1 {
		m.Region = region
	}
}
func (m *Mapping) setDurationIfNotSet(duration int64) {
	var blankDuration int64
	if m.DurationSeconds == blankDuration {
		m.DurationSeconds = duration
	}
}

func (m *Mapping) assumeNonSAML() (err error) {
	goslogger.Loggo.Debug("assuming non-SAML mapping")
	var sess *session.Session
	if m.parentAssumptions.atype == "primary" {
		sess, err = m.parentFlow.getPermSession()
		if err != nil {
			return err
		}
	} else if m.parentAssumptions.atype == "secondary" {
		var sponsorCred *sts.Credentials
		// try to locate sponsor creds for this secondary assumption
		if len(m.SponsorCredsArn) < 1 && len(m.parentFlow.PAss.Mappings) > 1 {
			msg := fmt.Sprintf("no sponsor_creds_arn specified for secondary mapping '%s' and too many primary mappings to make an inference", m.RoleArn)
			err = errors.New(msg)
		} else if len(m.SponsorCredsArn) < 1 {
			// means user didn't put anything in config file for sponsor creds
			// however, if there's only one set of primary creds we can infer
			goslogger.Loggo.Debug("detected missing sponsor creds arn in secondary mapping")
			if len(m.parentFlow.PAss.Mappings) == 1 {
				goslogger.Loggo.Debug("since only one set of creds in primary assumptions we'll take sponsorcreds from there")
				sponsorCred, err = m.parentFlow.PAss.getMappingCredential(m.parentFlow.PAss.Mappings[0].RoleArn)
			}
		} else {
			sponsorCred, err = m.parentFlow.PAss.getMappingCredential(m.SponsorCredsArn)
		}
		if err != nil {
			msg := fmt.Sprintf("error getting sponsor creds for secondary mapping: %s", err)
			err = errors.New(msg)
			return err
		}
		// now we can get our session from the sponsor
		sess, err = session.NewSessionWithOptions(session.Options{
			Config: aws.Config{Credentials: convertSCredsToCreds(sponsorCred)},
		})
		if err != nil {
			return err
		}
	}
	m.setDurationIfNotSet(m.parentAssumptions.durationSeconds)
	if sess != nil {
		m.credential, err = assumeRoleWithSession(
			&m.RoleArn,
			m.parentAssumptions.getRoleSessionName(),
			&m.DurationSeconds,
			sess,
		)
		goslogger.Loggo.Debug("set credential for mapping", "credential.AccessKeyId", *m.credential.AccessKeyId)
		if err != nil {
			return err
		}
	} else {
		err = errors.New("no session could be found to assume mapping")
	}
	return err
}

func (m *Mapping) assumeSAML() (err error) {
	m.credential, err = assumeSAMLRoleWithSession(
		&m.samlPrincipalArn,
		&m.RoleArn,
		m.parentSAMLConfig.roleSessionName,
		m.parentSAMLConfig.assertion,
		&m.DurationSeconds,
		m.parentSAMLConfig.stsClient,
	)
	return err
}

// assume attempts to handle the assumption of the mapping
func (m *Mapping) assume() (err error) {
	err = m.validate()
	if err != nil {
		return err
	}
	if m.parentSAMLConfig != nil {
		err = m.assumeSAML()
	} else {
		err = m.assumeNonSAML()
	}
	return err
}
