package gossamer

func newSamplePermMFA() (*PermCredsConfig) {
	pcc := PermCredsConfig{}
	mfa := MFA{}
	pcc.MFA = &mfa
	serial := CParam{}
	pcc.MFA.Serial = &serial
	pcc.MFA.Serial.name = "Serial"
	pcc.MFA.Serial.Source = "config"
	pcc.MFA.Serial.Value = "sampleserial"

	token := CParam{}
	pcc.MFA.Token = &token
	pcc.MFA.Token.name = "Token"
	pcc.MFA.Token.Source = "config"
	pcc.MFA.Token.Value = "sampletoken"
	return &pcc
}

func newSampleAssumptionsPrimary() (*Assumptions) {
	a := Assumptions{}
	m1 := newSampleMappingPrimary()
	m2 := newSampleMappingPrimary()
	m2.RoleArn = "arn:aws:iam::123456789012:role/role2"
	m2.ProfileName = "role2"
	m2.Region = ""
	m2.NoOutput = false
	a.Mappings = append(a.Mappings, *m1)
	a.Mappings = append(a.Mappings, *m2)
	return &a
}

func newSampleAssumptionsSecondary() (*Assumptions) {
	a := Assumptions{}
	m1 := newSampleMappingSecondary()
	a.Mappings = append(a.Mappings, *m1)
	return &a
}

func newSampleMappingPrimary() (*Mapping) {
	m := Mapping{}
	m.RoleArn = "arn:aws:iam::123456789012:role/sub-admin"
	m.ProfileName = "sub-admin"
	m.Region = "us-west-2"
	m.NoOutput = true
	return &m
}

func newSampleMappingSecondary() (*Mapping) {
	m := Mapping{}
	m.RoleArn = "arn:aws:iam::123456789012:role/admin"
	m.ProfileName = "admin"
	m.Region = "us-west-2"
	m.NoOutput = false
	m.SponsorCredsArn = "arn:aws:iam::123456789012:role/sub-admin"
	return &m
}

func newSampleSAMLConfig() (*SAMLConfig) {
	sc := SAMLConfig{}
	u := CParam{Source: "env", Value: "SAML_USER"}
	p := CParam{Source: "prompt"}
	url := CParam{Source: "config", Value: "https://my.saml.auth.url.com/auth.fcc"}
	t := CParam{Source: "config", Value: "https://my.auth.target.com/fss/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices" }
	sc.Username = &u
	sc.Password = &p
	sc.URL = &url
	sc.Target = &t
	return &sc
}

// GenerateConfigSkeleton sets up a sample Config object and 
// with a bunch of sample values set and returns it
func GenerateConfigSkeleton() (*Config) {
	gc := Config{}
    gc.OutFile = "./path/to/credentials/file"
    flow1 := Flow{
        Name: "sample-permanent-creds-mfa",
        AllowFailure: true,
        PermCredsConfig: newSamplePermMFA(),
		PAss: newSampleAssumptionsPrimary(),
    }
    gc.Flows = append(gc.Flows, &flow1)

	flow2 := Flow{
		Name: "sample-saml",
		AllowFailure: false,
		Region: "us-east-2",
		SAMLConfig: newSampleSAMLConfig(),
		PAss: newSampleAssumptionsPrimary(),
		SAss: newSampleAssumptionsSecondary(),
		DoNotPropagateRegion: true,
	}
	flow2.PAss.AllRoles = true
    gc.Flows = append(gc.Flows, &flow2)
	return &gc
}


