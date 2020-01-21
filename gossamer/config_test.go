package gossamer

import (
	"fmt"
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

func TestConfigValidation(t *testing.T) {
	initLog()
	cases := []struct {
        cfgString string
		Config *Config
		expectValid bool
	}{
		{
			cfgString: CONFIG_SAMPLE_1,
			expectValid: true,
		},
		{
			cfgString: CONFIG_SAMPLE_BAD_CPARAM,
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
		valid , err := c.Config.Validate()
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

var CONFIG_SAMPLE_BAD_CPARAM string = `output_file: ./path/to/credentials/file
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



var CONFIG_SAMPLE_1 string = `output_file: ./path/to/credentials/file
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

