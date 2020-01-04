package gossamer

import (
    "errors"
    "fmt"
    "github.com/aws/aws-sdk-go/service/sts"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/GESkunkworks/gossamer/goslogger"
)


// GetPAss handles the primary assumptions when using traditional keys
func (f *Flow) GetPAss() (err error) {
    sess, err := f.getPermSession()
    if err != nil { return err }
    for _, mapping := range(f.PAss.Mappings) {
        cred, err := assumeRoleWithSession(&mapping.RoleArn, f.PAss.getRoleSessionName(), sess)
        if err != nil {
            goslogger.Loggo.Error("Error assuming primary mapping",
                "PrimaryMapping", mapping.RoleArn,
                "flowType", f.credsType,
                "Error", err,
            )
        } else {
            f.PAss.setMappingCredential(mapping.RoleArn, cred)
            goslogger.Loggo.Info("Successfully assumed Primary Mapping",
                "mapping", mapping.RoleArn,
                "flowType", f.credsType,
                "cred", *cred.AccessKeyId,
            )
        }
    }
    strict := false
    err = f.PAss.validateMappings(strict)
    return err
}

// GetPAssSAML handles the SAML assumptions using the current desird configuration from the flow
func (f *Flow) GetPAssSAML() (err error) {
	samluser, err := f.SAMLConfig.Username.gather()
	if err != nil {return err}
	samlpass, err := f.SAMLConfig.Password.gather()
	if err != nil {return err}
	samlurl, err := f.SAMLConfig.URL.gather()
	if err != nil {return err}
	samltarget, err := f.SAMLConfig.Target.gather()
	if err != nil {return err}

	sc := newSAMLSessionConfig(f.Name, samluser, samlpass, samlurl, samltarget)
	err = sc.startSAMLSession()
	if err != nil {return err}

	rolesResult, err := sc.assumeSAMLRoles(f.PAss.AllRoles, f.PAss.getListOfArns())
	if err != nil {return err}
	goslogger.Loggo.Debug("flow > saml > AssumeSAMLRoles: done")
	// set the session name for later in case we need it for secondary assumptions
	f.roleSessionName = *sc.RoleSessionName

	err = f.PAss.buildMappings(rolesResult)
	if err != nil {return err}

	strict := false
	err = f.PAss.validateMappings(strict)
	if err != nil {return err}
	goslogger.Loggo.Debug("flow > saml > BuildMappings: done")
	return err
}

// ExecutePrimary runs the appropriate steps to complete the Primary Assumptions 
// auth flow for the detected flow type
func (f *Flow) ExecutePrimary() (err error) {
    switch f.credsType {
    case "saml":
        err = f.GetPAssSAML()
        if err != nil {return err}
    case "permanent":
        err = f.GetPAss()
        if err != nil {return err}
    default:
        err = errors.New("unable to determine flow type")
    }
    return err
}


// GetSAss goes through all of the secondary assumptions (if any) and collects credentials
// it's very lenient and only returns errors if they are critical.
func (f *Flow) GetSAss() (masterErr error) {
    goslogger.Loggo.Debug("starting flow > GetSAss", "name", f.Name)
    if !f.NoSAss() {
        // first we need to make absolutely sure we carry over the RoleSessionName for security purposes.
        rsn := f.PAss.getRoleSessionName()
        f.SAss.setRoleSessionName(*rsn)
        for _, sapping := range f.SAss.Mappings {
            var sponsorCred *sts.Credentials
            var err error
            if len(sapping.SponsorCredsArn) < 1 && len(f.PAss.Mappings) > 1 {
                // means we can't make any inferences
                msg := fmt.Sprintf("no sponsor_creds_arn specified for secondary mapping '%s' and too many primary mappings to make an inference", sapping.RoleArn)
                err = errors.New(msg)
            } else if len(sapping.SponsorCredsArn) < 1 {
                goslogger.Loggo.Debug("detected missing sponsor creds arn in secondary mapping")
                // means user didn't put anything in config file for sponsor creds
                // however, if there's only one set of primary creds we can infer
                if len(f.PAss.Mappings) == 1 {
                    goslogger.Loggo.Debug("since only one set of creds in primary assumptions we'll take sponsorcreds from there")
                    sponsorCred, err = f.PAss.getMappingCredential(f.PAss.Mappings[0].RoleArn)
                }
            } else {
                sponsorCred, err = f.PAss.getMappingCredential(sapping.SponsorCredsArn)
            }
            if err != nil {
                goslogger.Loggo.Error(
                    "Error with getting sponsor credentials, skipping SecondaryMapping",
                    "SponsorCredsArn", sapping.SponsorCredsArn,
                    "SecondaryMapping", sapping.RoleArn,
                    "error", err,
                )
            } else {
                sess, err := session.NewSessionWithOptions(session.Options{
                    Config: aws.Config{Credentials: convertSCredsToCreds(sponsorCred)},
                })
                if err != nil {
                    goslogger.Loggo.Error("Error establishing session with sponsorCreds",
                        "Error", err,
                    )
                } else {
                    cred, err := assumeRoleWithSession(&sapping.RoleArn, f.SAss.getRoleSessionName(), sess)
                    if err != nil {
                        goslogger.Loggo.Error("Error assuming secondary mapping",
                            "SecondaryMapping", sapping.RoleArn,
                            "Error", err,
                        )
                    } else {
                        f.SAss.setMappingCredential(sapping.RoleArn, cred)
                        goslogger.Loggo.Info("Successfully assumed Secondary Mapping",
                            "mapping", sapping.RoleArn,
                            "SponsorCredsArn", sapping.SponsorCredsArn,
                            "cred", *cred.AccessKeyId,
                        )
                    }
                }
            }
        }
        // now validate everything but we'll be lenient with creds
        strict := false
        masterErr = f.SAss.validateMappings(strict)
    } else {
        goslogger.Loggo.Info("no secondary assumptions detected so skipping", "flowname", f.Name)
    }
    return masterErr
}


