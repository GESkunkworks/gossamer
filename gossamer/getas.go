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
	for i := range f.PAss.Mappings {
		err = f.PAss.Mappings[i].assume()
		if err != nil {
			goslogger.Loggo.Error("Error assuming primary mapping",
				"PrimaryMapping", f.PAss.Mappings[i].RoleArn,
				"flowType", f.credsType,
				"Error", err,
			)
		} else {
			goslogger.Loggo.Info("Successfully assumed Primary Mapping",
				"mapping", f.PAss.Mappings[i].RoleArn,
				"flowType", f.credsType,
			)
		}
	}
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

	sc := newSAMLSessionConfig(f.Name, samluser, samlpass, samlurl, samltarget)
	err = sc.startSAMLSession()
	if err != nil {
		return err
	}

	err = sc.assumeSAMLRoles(f.PAss)
	if err != nil {
		return err
	}
	goslogger.Loggo.Debug("flow > saml > AssumeSAMLRoles: done")
	// set the session name for later in case we need it for secondary assumptions
	f.roleSessionName = *sc.roleSessionName
	if !f.AllowFailure {
		masterErr = err
	}
	return masterErr
}

// ExecutePrimary runs the appropriate steps to complete the Primary Assumptions
// auth flow for the detected flow type
func (f *Flow) ExecutePrimary() (err error) {
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

// GetSAss goes through all of the secondary assumptions (if any) and collects credentials
// it's very lenient and only returns errors if they are critical.
func (f *Flow) GetSAss() error {
	var masterErr error
	var err error
	goslogger.Loggo.Info("starting Primary assumptions", "flowName", f.Name)
	if !f.NoSAss() {
		// first we need to make absolutely sure we carry over the RoleSessionName for security purposes.
		rsn := f.PAss.getRoleSessionName()
		f.SAss.setRoleSessionName(*rsn)
		// run a precheck on the mappings to make sure stuff is set like duration
		for i := range f.SAss.Mappings {
			err = f.SAss.Mappings[i].assume()
			if err != nil {
				goslogger.Loggo.Error("Error assuming secondary mapping",
					"SecondaryMapping", f.SAss.Mappings[i].RoleArn,
					"Error", err,
				)
			} else {
				goslogger.Loggo.Info("Successfully assumed Secondary Mapping",
					"mapping", f.SAss.Mappings[i].RoleArn,
				)
			}
		}
	} else {
		goslogger.Loggo.Info("no secondary assumptions detected so skipping", "flowname", f.Name)
	}
	if !f.AllowFailure {
		masterErr = err
	}
	return masterErr
}
