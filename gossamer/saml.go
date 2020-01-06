package gossamer

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// XMLSAMLResponse is the top level struct for holding and unmarshaling the XML
// SAML assertion that comes back from the HTTP call
type XMLSAMLResponse struct {
	XMLName   xml.Name         `xml:"Response"`
	Assertion XMLSAMLAssertion `xml:"Assertion"`
}

// XMLSAMLAssertion is required for holding and unmarshaling the XML SAML
// assertion that comes back from the HTTP call.
type XMLSAMLAssertion struct {
	Issuer             string            `xml:"Issuer"`
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
	Name            string   `xml:"Name,attr"`
	AttributeValues []string `xml:"AttributeValue"`
}

func (sc *samlSessionConfig) decodeAssertion() (err error) {
	var parking []byte
	parking, err = base64.StdEncoding.DecodeString(*sc.assertion)
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
	var roles []*samlRole
	for _, val := range r.Assertion.AttributeStatement.AttributeValues {
		if val.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			for _, v := range val.AttributeValues {
				role, err := newRoleFromAttributeValue(v)
				if err != nil {
					return err
				}
				roles = append(roles, role)
			}
		}
		if val.Name == "https://aws.amazon.com/SAML/Attributes/RoleSessionName" {
			if len(val.AttributeValues) > 0 {
				sc.roleSessionName = &val.AttributeValues[0]
			}
		}
		if val.Name == "https://aws.amazon.com/SAML/Attributes/SessionDuration" {
			if len(val.AttributeValues) > 0 {
				sc.sessionDuration = &val.AttributeValues[0]
			}
		}
	}
	sc.roles = roles
	return err
}

// samlSessionConfig holds information required to begin
// the SAML session including things like the username/password
// and the URL
type samlSessionConfig struct {
	sessionName     *string
	roles           []*samlRole
	assertion       *string
	samlUser        *string
	samlPass        *string
	samlURL         *string
	samlTarget      *string
	roleSessionName *string
	sessionDuration *string
	stsClient       *sts.STS
}

func (sc *samlSessionConfig) getSessionDuration() (duration int64) {
	duration = 0
	if sc.sessionDuration != nil {
		var err error
		duration, err = strconv.ParseInt(*sc.sessionDuration, 10, 64)
		if err != nil {
			duration = 0
		}
	} else {
		goslogger.Loggo.Debug("SAML Assertion did not provide session duration, using default")
	}
	return duration
}

type samlRole struct {
	accountNumber string
	roleName      string
	roleArn       string
	principalArn  string
	identifier    string
}

// newSAMLSessionConfig returns a samlSessionConfig struct whose methods can be
// called to start a SAML session via HTTP and also assume roles that come back
// from the session's assertion
func newSAMLSessionConfig(sessionname, samluser, samlpass, samlurl, samltarget string) samlSessionConfig {
	var sc samlSessionConfig
	sc.sessionName = &sessionname
	sc.samlUser = &samluser
	sc.samlPass = &samlpass
	sc.samlURL = &samlurl
	sc.samlTarget = &samltarget
	return sc
}

// startSAMLSession attempts to make the HTTP calls required for obtaining
// the SAML assertion and use the response to decode a list of roles
// that could be assumed using the assertion
func (sc *samlSessionConfig) startSAMLSession() (err error) {
	err = sc.getAssertion()
	if err != nil {
		goslogger.Loggo.Debug("error getting SAML assertion", "error", err)
		return err
	}
	err = sc.decodeAssertion()
	if err != nil {
		// see if we can make a better error message for known errors
		if strings.Contains(err.Error(), "illegal base64") {
			message := fmt.Sprintf("error in decoding SAML assertion make sure password for user '%s' is correct", *sc.samlUser)
			err = errors.New(message)
		}
		goslogger.Loggo.Error("error attempting to decode SAML assertion", "error", err)
	}
	return err
}

func getRoleUniqueID(roleArn string) (uid *string, err error) {
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

func newRoleFromAttributeValue(raw string) (*samlRole, error) {
	role := samlRole{}
	var err error
	parn := strings.Split(raw, ",")
	if len(parn) != 2 {
		err = errors.New("error parsing PrincipalArn from saml:AttributeValue during comma split")
		return &role, err
	}
	role.principalArn = parn[1]

	role.roleArn = parn[0]
	rolename, accountnumber, err := parseRoleArn(role.roleArn)
	if err != nil {
		return &role, err
	}
	role.roleName = *rolename
	role.accountNumber = *accountnumber
	idTemp, err := getRoleUniqueID(role.roleArn)
	if err != nil {
		return &role, err
	}
	role.identifier = *idTemp
	return &role, err
}

func (sc *samlSessionConfig) getAssertion() (err error) {
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
	data.Set("username", *sc.samlUser)
	data.Set("password", *sc.samlPass)
	data.Set("target", *sc.samlTarget)
	req, err := http.NewRequest("POST", *sc.samlURL, bytes.NewBufferString(data.Encode()))
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
	sc.assertion = &samlassertion
	return err
}

// assumeSAMLRoles uses the previously obtained assertion to attempt to either assume
// all possible roles in the assertion as indicated by the allRoles input boolean
// or simply assume a preset list of mappings passed in with preAssumptions
// it returns a slice of gossamer.Mapping structs which can hold more metadata than the
// SAMLRoles that have been built thus far
func (sc *samlSessionConfig) assumeSAMLRoles(preAssumptions *Assumptions) (err error) {
	sc.stsClient = sts.New(session.Must(session.NewSession()))
	countSuccess := 0
	countFail := 0
	// add mappings from saml assertion we don't know about already
	for _, role := range sc.roles {
		var found bool
		found, _ = preAssumptions.getMapping(role.roleArn)
		if !preAssumptions.AllRoles && !found {
			goslogger.Loggo.Debug("Skipping role assumption per configuration directives", "role.roleArn", role.roleArn)
			continue
		} else if !found {
			var m *Mapping
			goslogger.Loggo.Debug("no user defined mapping found, creating new saml mapping", "roleArn", role.roleArn)
			m = newSAMLMapping(
				role.roleArn,
				role.principalArn,
				sc,
			)
			preAssumptions.Mappings = append(preAssumptions.Mappings, *m)
		} else {
			// set the saml stuff on the pre-known mapping
			preAssumptions.setMappingSAMLStuff(role.roleArn, role.principalArn, sc)
		}
	}
	// now that we have a bunch of new mappings we need to set relationships
	err = preAssumptions.setRelationships(preAssumptions.parentFlow, preAssumptions.parentConfig)
	if err != nil {
		return err
	}
	// now go through all the mappings and do the assumptions
	for i := range preAssumptions.Mappings {
		err = preAssumptions.Mappings[i].assume()
		if err != nil {
			countFail++
			goslogger.Loggo.Info("failed to assume SAML role", "error", err)
		} else {
			countSuccess++
		}
	}
	goslogger.Loggo.Info("Finished attempt at assuming roles in SAML Assertion", "successes", countSuccess, "failures", countFail)
	return err
}
