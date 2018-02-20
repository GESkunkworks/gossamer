package gossamer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rendicott/gossamer/goslogger"
)

func writeBufferToFile(filename string, b *bytes.Buffer) error {
	err := ioutil.WriteFile(filename, b.Bytes(), 0644)
	return err
}

func genTestArnsJSON() (*bytes.Buffer, error) {
	seed := `{"Roles": [
		{"RoleArn": "arn:aws:iam::123456789101:role/prod-role",
		"AccountName": "prod-account",
	    "Region": "us-east-1"}, 
		{"RoleArn": "arn:aws:iam::110987654321:role/dev-role",
		"AccountName": "dev-account",
	    "Region": "us-west-2"}]}`
	var b bytes.Buffer
	_, err := b.WriteString(seed)
	if err != nil {
		fmt.Println("error: ", err)
		return &b, err
	}
	return &b, err
}

func deleteFile(filename string) {
	err := os.Remove(filename)
	if err != nil {
		panic(err)
	}
}

func TestLoadArnsFile(t *testing.T) {
	testRoleFileName := "gossamer_test_json.json"
	b, err := genTestArnsJSON()
	if err != nil {
		t.Errorf("unable to seed test data: %s", err)
	}
	err = writeBufferToFile(testRoleFileName, b)
	if err != nil {
		t.Errorf("unable to write test file: %s", err)
	}
	accounts, err := LoadArnsFile(testRoleFileName)
	if err != nil {
		t.Errorf("Error loading file: %s", err)
	}
	if (len(accounts) < 2) || len(accounts) > 2 {
		t.Errorf("Number of arns loaded incorrect, got: %d, want: %d.", len(accounts), 2)
	}
	for _, acct := range accounts {
		if reflect.TypeOf(acct.AccountName).String() != "string" {
			t.Errorf("AccountName not string")
		}
		if reflect.TypeOf(acct.RoleArn).String() != "string" {
			t.Errorf("RoleArn not string")
		}
		if reflect.TypeOf(acct.Region).String() != "string" {
			t.Errorf("Region not string")
		}
	}
	defer deleteFile(testRoleFileName)
}

func buildRunnerOpts() RunnerOptions {
	// build out option defaults then modify
	var renewThreshold, seconds, sessionDuration int64
	renewThreshold = 10
	seconds = 300
	sessionDuration = 3600
	var accts []Account

	opts := RunnerOptions{
		OutFile:         "./gossamer_creds",
		Accounts:        accts,
		RoleSessionName: "gossamer",
		Profile:         "",
		SerialNumber:    "",
		TokenCode:       "",
		RenewThreshold:  float64(renewThreshold),
		Seconds:         float64(seconds),
		SessionDuration: sessionDuration,
		DaemonFlag:      false,
		Mode:            "instance-profile",
		Region:          "us-east-1",
		Force:           false}
	return opts
}

func TestModeDeciderMFA(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Profile = "iam"
	ropts.SerialNumber = "GADT000012345"
	ropts.DaemonFlag = false
	ropts.TokenCode = "123456"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      "us-east-1"}
	ropts.OutFile = "./gossamer_test_MFA.txt"
	ropts.Accounts = append(ropts.Accounts, acct)
	got := ModeDecider(&ropts)
	want := "mfa"
	if got != want {
		t.Errorf("Mode detection failed. Wanted: '%s', Got: '%s'", want, got)
	}
}

func TestMFASerialNoValidation(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Profile = "iam"
	ropts.SerialNumber = "ABC000123FT"
	ropts.DaemonFlag = false
	ropts.TokenCode = "123456"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      "us-east-1"}
	ropts.OutFile = "./gossamer_test_MFA.txt"
	ropts.Accounts = append(ropts.Accounts, acct)
	got := ModeDecider(&ropts)
	want := "mfa"
	if got != want {
		t.Errorf("Mode detection failed. Wanted: '%s', Got: '%s'", want, got)
	}
}
func TestMFABadCreds(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Profile = "iam"
	ropts.SerialNumber = "GADT000012345"
	ropts.DaemonFlag = false
	ropts.TokenCode = "123456"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      "us-east-1"}
	ropts.OutFile = "./gossamer_test_MFA.txt"
	err := generateTestCredFile(ropts.OutFile, "iam")
	ropts.Accounts = append(ropts.Accounts, acct)
	ropts.Mode = ModeDecider(&ropts)
	err = GenerateNewMfa(&ropts, ropts.Accounts)
	expectedErr := "ExpiredToken: The security token included in the request is expired"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Expected: '%s', Got: '%s'", expectedErr, err)
	}
}

func TestModeDeciderInstanceProfile(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Accounts = []Account{}
	ropts.OutFile = "./gossamer_test_instance_profile.txt"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      ropts.Region}
	ropts.Accounts = append(ropts.Accounts, acct)
	ropts.DaemonFlag = false
	got := ModeDecider(&ropts)
	want := "instance-profile"
	if got != want {
		t.Errorf("Mode detection failed. Wanted: '%s', Got: '%s'", want, got)
	}
}

func TestModeDeciderProfileOnly(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Profile = "saml"
	ropts.Accounts = []Account{}
	ropts.OutFile = "./gossamer_test_mode_decider.txt"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      ropts.Region}
	ropts.Accounts = append(ropts.Accounts, acct)
	ropts.DaemonFlag = false
	got := ModeDecider(&ropts)
	want := "profile-only"
	if got != want {
		t.Errorf("Mode detection failed. Wanted: '%s', Got: '%s'", want, got)
	}
}

func TestModeDeciderMfaNoAssume(t *testing.T) {
	ropts := buildRunnerOpts()
	ropts.Profile = "saml"
	ropts.Accounts = []Account{}
	ropts.OutFile = "./gossamer_test_mode_decider.txt"
	ropts.DaemonFlag = false
	ropts.Mode = "mfa_noassume"
	got := ModeDecider(&ropts)
	want := "profile-only"
	if got != want {
		t.Errorf("Mode detection failed. Wanted: '%s', Got: '%s'", want, got)
	}
}

func generateTestExpireFile(filename string, expires string) error {
	var b bytes.Buffer
	_, err := b.WriteString(expires)
	if err != nil {
		fmt.Println(err)
	}
	err = writeBufferToFile(filename, &b)
	return err
}

func generateTestCredFile(filename string, entryName string) error {
	var b bytes.Buffer
	_, err := b.WriteString("[" + entryName + "]\n")
	_, err = b.WriteString("output = json\n")
	_, err = b.WriteString("region = us-east-1\n")
	_, err = b.WriteString("aws_access_key_id = ASIAJASDFEFOIFJCAFXAQ\n")
	_, err = b.WriteString("aws_secret_access_key = uHOawoeifaowinafoiawi/eoia asdf/14bocE1pNtd4\n")
	_, err = b.WriteString("aws_session_token = FQoDYXdzEN///////////wEaDBBebVjaMasRQbNcYCKvAZfpQw5TGWUSydHYx5rrMx1royMnMJx+ZK781kiFbifoAh1p5DXWOeY1xrMX93iw3uDEOPMvN5lTNWACOsRqXSgCkbHY/HYD13NnZjQUZ/bGQJMbFxpQ6Z+LuaL5nJY0oUc54NPRTVZTUqTu1ePnnJopYr/+9V7elY+KP0DSNDFWtXg4Z6/OjJPJoSKE8SYN3KgpVJ2gVUC6xfjEtzT7PcvhY+H1j2iTKNdICoD4KjMo5feXyQU=\n")
	if err != nil {
		fmt.Println(err)
	}
	err = writeBufferToFile(filename, &b)
	return err
}

func TestReadExpireNoFile(t *testing.T) {
	// build opts
	ropts := buildRunnerOpts()
	ropts.Accounts = []Account{}
	ropts.OutFile = "./gossamer_test_expire_file.txt"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      ropts.Region}
	ropts.Accounts = append(ropts.Accounts, acct)
	ropts.DaemonFlag = false
	// now build expires file
	got, err := ReadExpire(ropts.OutFile, ropts.RenewThreshold)
	if err != nil {
		t.Errorf("Got err in test read expire: '%s'", err)
	}
	want := true
	if got != want {
		t.Errorf("ReadExpire failed. Wanted: '%t', Got: '%t'", got, want)
	}
	defer deleteFile(ropts.OutFile)
}

func TestReadExpire(t *testing.T) {
	// build opts
	ropts := buildRunnerOpts()
	ropts.Accounts = []Account{}
	ropts.OutFile = "./gossamer_test_expire_file.txt"
	acct := Account{RoleArn: "arn:aws:iam::123456789101:role/prod-role",
		AccountName: "prod-account",
		Region:      ropts.Region}
	ropts.Accounts = append(ropts.Accounts, acct)
	ropts.DaemonFlag = false
	// now build expires file
	expires := expiresToken + "2017-05-17 23:12:25 +0000 UTC"
	err := generateTestExpireFile(ropts.OutFile, expires)
	got, err := ReadExpire(ropts.OutFile, ropts.RenewThreshold)
	if err != nil {
		t.Errorf("Got err in test read expire: '%s'", err)
	}
	want := true
	if got != want {
		t.Errorf("ReadExpire failed. Wanted: '%t', Got: '%t'", got, want)
	}
	defer deleteFile(ropts.OutFile)
}

func TestMain(m *testing.M) {
	// set up global logging for running tests
	daemonFlag := false
	logFile := "./gossamer_tests_log.json"
	loglevel := "info"
	goslogger.SetLogger(daemonFlag, logFile, loglevel)
	retCode := m.Run()
	os.Exit(retCode)
}
