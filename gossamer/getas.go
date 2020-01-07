// Package gossamer is a toolkit for assuming AWS roles concurrently
// via permanent credentials or SAML. Its behavior is driven by a Config struct
// that defines auth flows that are defined by their starter credentials,
// the primary mappings, and secondary mappings.
// Mappings are a concept of a role ARN tied to a profile entry name with
// some additional metadata. Secondary mappings are aware that they must
// be assumed using a previously established primary mapping.
//
// Each flow can then be executed using its Execute method which will run
// the appropriate auth flow and collect the mappings' credentials.
//
// After the flow has been executed the GetAcfmgrProfileInputs method
// can be called in order to collect the results of the mappings as
// inputs for the Acfmgr package which is a helper utility for writing
// AWS credential profile entries to a file.
//
package gossamer

import (
	"errors"
	"github.com/GESkunkworks/gossamer/goslogger"
)

// GetPAss handles the primary assumptions when using traditional keys
func (f *Flow) GetPAss() error {
	var masterErr error
	var err error
	goslogger.Loggo.Info("starting Primary assumptions", "flowName", f.Name)
	f.PAss.assumeMappingsConcurrent()
	if !f.AllowFailure {
		masterErr = err
	}
	return masterErr
}

// GetPAssSAML handles the SAML assumptions using the current desird configuration from the flow
func (f *Flow) GetPAssSAML() error {
	var masterErr error
	var err error
	samluser, err := f.SAMLConfig.Username.gather()
	if err != nil {
		return err
	}
	samlpass, err := f.SAMLConfig.Password.gather()
	if err != nil {
		return err
	}
	samlurl, err := f.SAMLConfig.URL.gather()
	if err != nil {
		return err
	}
	samltarget, err := f.SAMLConfig.Target.gather()
	if err != nil {
		return err
	}

	sc := newSAMLSessionConfig(
		f.Name, samluser, samlpass, samlurl, samltarget, f.SAMLConfig.AllowMappingDurationOverride,
	)
	err = sc.startSAMLSession()
	if err != nil {
		return err
	}
	// set the session name for later in case we need it for secondary assumptions
	goslogger.Loggo.Debug("setting roleSessionName on assumptions", "roleSessionName", *sc.roleSessionName)
	f.PAss.setRoleSessionName(*sc.roleSessionName)

	err = sc.assumeSAMLRoles(f.PAss)
	if !f.AllowFailure {
		masterErr = err
	}
	return masterErr
}

// Execute detects the flow type and runs the appropriate steps to complete
// either the primary or secondary assumptions
func (f *Flow) Execute() (err error) {
	// every flow always has a primary
	err = f.executePrimary()
	if err != nil {
		return err
	}
	err = f.executeSecondary()
	return err
}

// executePrimary runs the appropriate steps to complete the Primary Assumptions
// auth flow for the detected flow type
func (f *Flow) executePrimary() (err error) {
	switch f.credsType {
	case "saml":
		err = f.GetPAssSAML()
		if err != nil {
			return err
		}
	case "permanent":
		err = f.GetPAss()
		if err != nil {
			return err
		}
	default:
		err = errors.New("unable to determine flow type")
	}
	return err
}

// executeSecondary goes through all of the secondary assumptions (if any) and collects credentials
// it's very lenient and only returns errors if they are critical.
func (f *Flow) executeSecondary() error {
	var masterErr error
	var err error
	if !f.NoSAss() {
		goslogger.Loggo.Info("starting secondary assumptions", "flowName", f.Name)
		// first we need to make absolutely sure we carry over the RoleSessionName for security purposes.
		rsn := f.PAss.getRoleSessionName()
		f.SAss.setRoleSessionName(*rsn)
		// run a precheck on the mappings to make sure stuff is set like duration
		f.SAss.assumeMappingsConcurrent()
	} else {
		goslogger.Loggo.Info("no secondary assumptions detected so skipping", "flowname", f.Name)
	}
	if !f.AllowFailure {
		masterErr = err
	}
	return masterErr
}
