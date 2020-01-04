package gossamer

import (
    "encoding/base64"
    "encoding/xml"
    "encoding/json"
    "strings"
    "net/http"
    "net/url"
    "io"
    "net/http/cookiejar"
    "golang.org/x/net/publicsuffix"
    "golang.org/x/net/html"
    "bytes"
    "errors"
    "github.com/aws/aws-sdk-go/service/sts"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/GESkunkworks/gossamer/goslogger"
    "fmt"
    "regexp"
)

// XMLSAMLResponse is the top level struct for holding and unmarshaling the XML
// SAML assertion that comes back from the HTTP call
type XMLSAMLResponse struct {
    XMLName xml.Name `xml:"Response"`
    Assertion XMLSAMLAssertion `xml:"Assertion"`
}
// XMLSAMLAssertion is required for holding and unmarshaling the XML SAML
// assertion that comes back from the HTTP call. 
type XMLSAMLAssertion struct {
    Issuer string `xml:"Issuer"`
    AttributeStatement XMLSAMLAttributes `xml:"AttributeStatement"`
}

// XMLSAMLAttributes is required for holding and unmarshaling the XML SAML
// assertion that comes back from the HTTP call. 
type XMLSAMLAttributes struct {
    AttributeValues []XMLSAMLAttribute `xml:"Attribute"`
}

// XMLSAMLAttribute is required for holding and unmarshaling the XML SAML
// assertion that comes back from the HTTP call. 
type XMLSAMLAttribute struct {
    Name string `xml:"Name,attr"`
    AttributeValues []string `xml:"AttributeValue"`
}

func (sc *SAMLSessionConfig) decodeAssertion() (err error) {
    var parking []byte
    parking, err = base64.StdEncoding.DecodeString(*sc.Assertion)
    if err != nil {
        goslogger.Loggo.Error("error decoding base64 SAML assertion", "error", err)
        return err
    }
    assertionLength := len(parking)
    goslogger.Loggo.Debug("got bas64 decoded assertion", "bytes", assertionLength)
    if assertionLength < 1 {
        err = errors.New("got SAML assertion of length zero please check url/target settings and check with SAML provider")
        return err
    }
    var r XMLSAMLResponse
    err = xml.Unmarshal(parking, &r)
    if err != nil {
        goslogger.Loggo.Error("error unmarshaling SAML assertion to xml struct")
        return err
    }
    var roles []*SAMLRole
    for _, val := range(r.Assertion.AttributeStatement.AttributeValues) {
        if val.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
            for _, v := range(val.AttributeValues) {
                role, err := newRoleFromAttributeValue(v)
                if err != nil {
                    return err
                }
                roles = append(roles, role)
            }
        }
        if val.Name == "https://aws.amazon.com/SAML/Attributes/RoleSessionName" {
            if len(val.AttributeValues) > 0 {
                sc.RoleSessionName = &val.AttributeValues[0]
            }
        }
        if val.Name == "https://aws.amazon.com/SAML/Attributes/SessionDuration" {
            if len(val.AttributeValues) > 0 {
                sc.SessionDuration = &val.AttributeValues[0]
            }
        }
    }
    sc.Roles = roles
	return err
}

type SAMLSessionConfig struct {
    SessionName *string
    Roles []*SAMLRole `json:"Roles"`
    Assertion *string `json:"Assertion"`
    SamlUser *string
    samlPass *string
    SamlUrl *string
    SamlTarget *string
    RoleSessionName *string `json:"RoleSessionName"`
    SessionDuration *string `json:"SessionDuration"`
}

type SAMLRole struct {
    AccountNumber string `json:"AccountNumber"`
    RoleName string
    RoleArn string
    PrincipalArn string
    Result *sts.AssumeRoleWithSAMLOutput
    Identifier string
}

// dump returns a formatted string of the current SAMLSessionConfig struct
// which is useful for displaying configuration to the user and debugging.
func (sc *SAMLSessionConfig) dump() (string) {
    tempo := []byte{}
    tempo, _ = json.Marshal(sc)
    return string(tempo)
}

// newSAMLSessionConfig returns a SAMLSessionConfig struct whose methods can be 
// called to start a SAML session via HTTP and also assume roles that come back
// from the session's assertion
func newSAMLSessionConfig(sessionname, samluser, samlpass, samlurl, samltarget string) (SAMLSessionConfig) {
    var sc SAMLSessionConfig
    sc.SessionName = &sessionname
    sc.SamlUser = &samluser
    sc.samlPass = &samlpass
    sc.SamlUrl = &samlurl
    sc.SamlTarget = &samltarget
    return sc
}

// startSAMLSession attempts to make the HTTP calls required for obtaining
// the SAML assertion and use the response to decode a list of roles
// that could be assumed using the assertion
func (sc *SAMLSessionConfig) startSAMLSession() (err error) {
    err = sc.getAssertion()
    if err != nil {
        goslogger.Loggo.Debug("error getting SAML assertion", "error", err)
        return err
    }
    err = sc.decodeAssertion()
    if err != nil {
        // see if we can make a better error message for known errors
        if strings.Contains(err.Error(), "illegal base64") {
            message := fmt.Sprintf("error in decoding SAML assertion make sure password for user '%s' is correct", *sc.SamlUser)
            err = errors.New(message)
        }
        goslogger.Loggo.Error("error attempting to decode SAML assertion", "error", err)
    }
    return err
}

func getRoleUniqueId(roleArn string) (uid *string, err error) {
    rolename, accountnumber, err := parseRoleArn(roleArn)
    if err != nil {
        return uid, err
    }
    uidTemp := fmt.Sprintf("%s_%s", *accountnumber, *rolename)
    return &uidTemp, err
}

func parseRoleArn(roleArn string) (rolename, accountnumber *string, err error) {
    chunks := strings.Split(roleArn, ":")
    if len(chunks) < 6 {
        err = errors.New("error parsing role and accountnumber from roleArn during colon split")
        return rolename, accountnumber, err
    }
    accountnumber = &chunks[4]
    accountnumberRegex := regexp.MustCompile("[0-9]{12}")
    if !accountnumberRegex.MatchString(*accountnumber) {
        err = errors.New("string from expected location in arn does not match account number regex")
        return rolename, accountnumber, err
    }
    roletemp := strings.Split(chunks[5], "/")
    roletemp2 := strings.Join(roletemp[1:], "/")
    rolename = &roletemp2
    return rolename, accountnumber, err
}

func newRoleFromAttributeValue(raw string) (*SAMLRole, error) {
    role := SAMLRole{}
    var err error
    parn := strings.Split(raw, ",")
    if len(parn) != 2 {
        err = errors.New("Error parsing PrincipalArn from saml:AttributeValue during comma split")
        return &role, err
    } else {
        role.PrincipalArn = parn[1]
    }

    role.RoleArn = parn[0]
    rolename, accountnumber, err := parseRoleArn(role.RoleArn)
    if err != nil {
        return &role, err
    }
    role.RoleName = *rolename
    role.AccountNumber = *accountnumber
    idTemp, err := getRoleUniqueId(role.RoleArn)
    if err != nil {
        return &role, err
    }
    role.Identifier = *idTemp
    return &role, err
}

func (sc *SAMLSessionConfig) getAssertion() (err error) {
    var samlassertion string
    // set up cookie jar
    jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
    if err != nil {
        return err
    }
    client := &http.Client{
        Jar: jar,
    }
    data := url.Values{}
    data.Set("username", *sc.SamlUser)
    data.Set("password", *sc.samlPass)
    data.Set("target", *sc.SamlTarget)
    req, err := http.NewRequest("POST", *sc.SamlUrl, bytes.NewBufferString(data.Encode()))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
    if err != nil {
        return err
    }

    resp, err := client.Do(req)
    if err != nil {
        goslogger.Loggo.Debug("error in SAML client.Do", "error", err)
        return err
    }
    defer resp.Body.Close()
    z := html.NewTokenizer(resp.Body)
    count := 0
    done := false
    for {
        count++
        if done {
            break
        }
        tt := z.Next()
        tn, _ := z.TagName()
        switch {
        case tt == html.ErrorToken:
            err := z.Err()
            if err == io.EOF {
                done = true
            } else {
                done = true
                return err
            }
            break
        case string(tn) == "input":
            for {
                k, v, more := z.TagAttr()
                if string(k) == "value" {
                    samlassertion = string(v)
                }
                if !more {
                    break
                }
            }
        }
    }
    sc.Assertion = &samlassertion
    return err
}

// assumeSAMLRoles uses the previously obtained assertion to attempt to either assume
// all possible roles in the assertion as indicated by the allRoles input boolean
// or simply assume a preset list of roleArns as passed in via the []string
// it returns a slice of gossamer.Mapping structs which can hold more metadata than the
// SAMLRoles that have been built thus far
func (sc *SAMLSessionConfig) assumeSAMLRoles(allRoles bool, roleArns []string) (mappings []*Mapping, err error) {
    client := sts.New(session.New())
    count_success := 0
    count_fail := 0
    for _, role := range(sc.Roles) {
        var m Mapping
        if !allRoles && !contains(roleArns, role.RoleArn) {
            goslogger.Loggo.Debug("Skipping role assumption per configuration directives", "role.RoleArn", role.RoleArn)
            continue
        }
        input := sts.AssumeRoleWithSAMLInput{
            PrincipalArn: &role.PrincipalArn,
            RoleArn: &role.RoleArn,
            SAMLAssertion: sc.Assertion,
        }
        result, err := client.AssumeRoleWithSAML(&input)
        if err != nil {
            count_fail++
            goslogger.Loggo.Info("Error assuming role", "FlowName", *sc.SessionName, "Error", err.Error(), "RoleName", role.RoleName, "RoleArn", role.RoleArn )
        } else {
            role.Result = result
            m.RoleArn = role.RoleArn
            m.ProfileName = role.Identifier
            m.credential = result.Credentials
            mappings = append(mappings, &m)
            count_success++
            goslogger.Loggo.Info("Successfully assumed role", "FlowName", *sc.SessionName, "Identifier", role.Identifier, "RoleArn", role.RoleArn, "AccessKeyId", *role.Result.Credentials.AccessKeyId)
        }
    }
    goslogger.Loggo.Info("Finished attempt at assuming roles in SAML Assertion", "successes", count_success, "failures", count_fail)
    return mappings, err
}


func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}



