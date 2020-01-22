package gossamer

import (
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestSetRelationships(t *testing.T) {
	initLog()
	cases := []struct {
		Config *Config
	}{
		{
			Config: GenerateConfigSkeleton(),
		},
	}

	for i, c := range cases {
		fmt.Println("test case: ", i)
		err := c.Config.setRelationships()
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	}
}

func TestCParamGather(t *testing.T) {
	initLog()
	cases := []struct {
		param       CParam
		envName     string
		expectValue string
		expectError bool
	}{
		{
			param:       newCParamEnv("COOL"),
			envName:     "COOL",
			expectValue: "dude",
			expectError: false,
		},
		{
			param:       newCParamEnv("COOL2"),
			envName:     "",
			expectValue: "",
			expectError: true,
		},
	}

	for i, c := range cases {
		fmt.Println("test case: ", i)
		if c.envName != "" {
			// means we need to preset the ENV var
			os.Setenv(c.envName, c.expectValue)
		}
		val, err := c.param.gather()
		if err != nil && c.expectError == false {
			t.Errorf("unexpected error gathering CParam: %s", err)
		}
		if val != c.expectValue {
			t.Errorf("unexpected result, expected '%s', got '%s'",
				c.expectValue, val)
		}
	}

}

func newCParamEnv(envName string) CParam {
	cp := CParam{
		name:       "cool",
		Source:     "env",
		Value:      envName,
		parentflow: "cooflow",
	}
	return cp
}

func TestConfigValidation(t *testing.T) {
	initLog()
	cases := []struct {
		cfgString   string
		Config      *Config
		expectValid bool
	}{
		{
			cfgString:   configSampleGood1,
			expectValid: true,
		},
		{
			cfgString:   configSampleBadCParam,
			expectValid: false,
		},
		{
			cfgString:   configSampleBadPermSpelling,
			expectValid: false,
		},
		{
			cfgString:   configSampleMissingAssumptions,
			expectValid: false,
		},
	}

	var err error
	for i, c := range cases {
		fmt.Println("test case: ", i)
		c.Config, err = loadConfigFromString(c.cfgString)
		if err != nil {
			t.Errorf("unexpected error loading config: %s", err)
		}
		valid, err := c.Config.Validate()
		if err != nil && c.expectValid == true {
			t.Errorf("unexpected error validating config: %s", err)
		}
		t.Logf("error: %s, valid %t", err, valid)
		if valid != c.expectValid {
			t.Errorf("unexpected result, expected '%t', got '%t'",
				c.expectValid, valid)
		}
	}
}

func loadConfigFromString(cfg string) (gc *Config, err error) {
	localC := Config{}
	bc := []byte(cfg)
	err = yaml.Unmarshal(bc, &localC)
	gc = &localC
	return gc, err
}

var configSampleBadCParam string = `output_file: ./path/to/credentials/file
flows:
- name: bad-perm-cred-example
  permanent:
    mfa:
      serial:
        source: magic # adding bad value here to fail test
        value: sampleserial
      token:
        source: config
        value: sampletoken
  primary_assumptions:
    all_roles: false
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
      no_output: true
      session_duration_seconds: 43200
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
      session_duration_seconds: 43200
  do_not_propagate_region: false
  allow_failure: true`

var configSampleGood1 string = `output_file: ./path/to/credentials/file
flows:
- name: sample-permanent-creds-mfa
  permanent:
    mfa:
      serial:
        source: config
        value: sampleserial
      token:
        source: config
        value: sampletoken
  primary_assumptions:
    all_roles: false
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
      no_output: true
      session_duration_seconds: 43200
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
      session_duration_seconds: 43200
  do_not_propagate_region: false
  allow_failure: true
- name: sample-saml
  saml_config:
    username:
      source: env
      value: SAML_USER
    password:
      source: prompt
    url:
      source: config
      value: https://my.saml.auth.url.com/auth.fcc
    target:
      source: config
      value: https://my.auth.target.com/fss/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices
    allow_mapping_duration_override: true
  primary_assumptions:
    all_roles: true
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
      no_output: true
      session_duration_seconds: 43200
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
      session_duration_seconds: 43200
  secondary_assumptions:
    all_roles: false
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/admin
      profile_name: admin
      region: us-west-2
      sponsor_creds_arn: arn:aws:iam::123456789012:role/sub-admin
  session_duration_seconds: 43200
  region: us-east-2
  do_not_propagate_region: true
  allow_failure: false`

var configSampleBadPermSpelling string = `output_file: ./path/to/credentials/file
flows:
- name: bad-perm-spelling-example
  premanent:
    mfa:
      serial:
        source: config # adding bad value here to fail test
        value: sampleserial
      token:
        source: config
        value: sampletoken
  primary_assumptions:
    all_roles: false
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
      no_output: true
      session_duration_seconds: 43200
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
      session_duration_seconds: 43200
  do_not_propagate_region: false
  allow_failure: true`

var configSampleMissingAssumptions string = `output_file: ./path/to/credentials/file
flows:
- name: missing-assumptions
  permanent:
    mfa:
      serial:
        source: config # adding bad value here to fail test
        value: sampleserial
      token:
        source: config
        value: sampletoken`
