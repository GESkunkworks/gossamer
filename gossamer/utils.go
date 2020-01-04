package gossamer

import (
	"encoding/json"
	"errors"
	"os"
    "io/ioutil"
    "github.com/GESkunkworks/gossamer/goslogger"
    "gopkg.in/yaml.v2"

)

// LegacyAccount just holds the rolearn, region, and
// account name for each entry to build from
type LegacyAccount struct {
    RoleArn     string
    AccountName string
    Region      string
}

// legacyConfiguration holds a list of
// legacy Account structs
type legacyConfiguration struct {
    Roles []LegacyAccount
}

// loadLegacyRolesFile returns a slice of Account structs loaded
// from a legacy gossamer roles file
func loadLegacyRolesFile(filename string) ([]LegacyAccount, error) {
    config := legacyConfiguration{}
    file, err := os.Open(filename)
    if err != nil {
        return config.Roles, err
    }
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&config)
    if err != nil {
        return config.Roles, err
    }
    goslogger.Loggo.Debug("done loading rolesfile", "num_roles", len(config.Roles))
    return config.Roles, err
}

func convertAcctsToMappings(accounts []LegacyAccount) (mappings []Mapping) {
	for _, account := range(accounts) {
		m := Mapping{
			RoleArn: account.RoleArn,
			ProfileName: account.AccountName,
			Region: account.Region,
		}
		mappings = append(mappings, m)
	}
    goslogger.Loggo.Debug("converted roles to mappings", "num_roles", len(accounts), "num_mappings", len(mappings))
    return mappings
}

func convertLegacyRolesToMappings(filename string) (mappings []Mapping, err error) {
	accounts, err := loadLegacyRolesFile(filename)
	mappings = convertAcctsToMappings(accounts)
	if err != nil { return mappings, err }
	return mappings, err
}

func (gc *Config) ConvertLegacyFlagsToConfig(gfl *GossFlags) (err error) {
    goslogger.Loggo.Debug("Legacy: starting ConvertLegacyFlagsToConfig")
	var mappings []Mapping
	var accounts []LegacyAccount
    gc.OutFile = gfl.OutFile
	flow := Flow{Name: "gossamer-legacy"}
    if gfl.RolesFile != "" {
        goslogger.Loggo.Debug("Legacy: attempting to convert legacy roles roles file to mappings")
        mappings, err = convertLegacyRolesToMappings(gfl.RolesFile)
        if err != nil {
            return(err)
        }
    }
    if gfl.Region != "" {
        flow.Region = gfl.Region
    }
    if gfl.RoleArn == "" && gfl.RolesFile == "" {
		err = errors.New("Legacy: must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		return err
    }
	if gfl.RoleArn != "" && gfl.RolesFile == "" {
        // just building one account struct
        acct := LegacyAccount{RoleArn: gfl.RoleArn, AccountName: gfl.ProfileEntryName, Region: gfl.Region}
        accounts = append(accounts, acct)
		mappings = convertAcctsToMappings(accounts)
    }
	if len(mappings) == 0 {
		err = errors.New("must specify role ARN with '-a' or '-rolesfile'. Exiting.")
		return err
    }
	if 900 > gfl.SessionDuration {
		err = errors.New("sessionDuration is outside threshold min=900")
		return err
    }
	// now we have enough to build our flow hopefully
    goslogger.Loggo.Debug("Legacy: done attempting to getting mappings", "len(mappings)", len(mappings))
	if len(mappings) > 0 {
        as := Assumptions{}
        flow.PAss = &as
		flow.PAss.Mappings = mappings
        pcc := PermCredsConfig{}
		flow.PermCredsConfig = &pcc
		if len(gfl.SerialNumber) > 0 && len(gfl.TokenCode) > 0  {
			flow.PermCredsConfig = newSamplePermMFA()
			flow.PermCredsConfig.MFA.Serial.Value = gfl.SerialNumber
			flow.PermCredsConfig.MFA.Token.Value = gfl.TokenCode
		}
		if len(gfl.Profile) > 0 {
			flow.PermCredsConfig.ProfileName = gfl.Profile
		}
	}
    gc.Flows = append(gc.Flows, &flow)
    if gfl.GeneratedConfigOutputFile != "" && gfl.GeneratedConfigOutputFile != "@sample" {
		goslogger.Loggo.Info("attempting to generate config file from translated arguments")
		err = WriteConfigToFile(gc, gfl.GeneratedConfigOutputFile)
		if err != nil { return err }
	}
	goslogger.Loggo.Info("wrote configuration to file", "filename", gfl.GeneratedConfigOutputFile)
	return err
}


// WriteConfigToFile takes a Config object and writes it to the desired
// filename 
func WriteConfigToFile(gc *Config, filename string) (err error) {
    dataBytes, err := yaml.Marshal(gc)
    if err != nil { return err }
    err = ioutil.WriteFile(filename, dataBytes, 0644)
    return err
}

