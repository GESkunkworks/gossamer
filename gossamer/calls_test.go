package gossamer

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/GESkunkworks/gossamer/goslogger"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

func initLog() {
	goslogger.SetLoggerTesting("debug")
}

func getFakeCreds() *sts.Credentials {
	timeFormat := "2006-01-02T15:04:05Z" // time.RFC3339
	t, _ := time.Parse(timeFormat, "2020-01-08T14:03:02Z")
	st := "f8sNh8tocFpiabpbOGHfpqSYSgOQcNqvbzyNpAYW9gxWOlAcGpaPJMQoeD" +
		"M/0AQjHnvA8qMA8Q2jdxFmPwLHA184JI9YXVXs3a6ig2GMKvtTYXYwe4HK" +
		"bymJm4zWxcG7OWwPee8BlZbY+F/T+lmNguge42ePV3mA5uyK5oTgryTG9" +
		"TNFBtmh518OCdRXBDwwPWwQbfLWM/95KaOnZRIr/TpkjdWk4iCFXmKTIs5" +
		"RKwDrS9mmD66cj6KTNsAGDxw29wYLOXlcB3MXbuEZzgew6tn8vpzonBIRi" +
		"Fy74Oym6Ct1sFcNXVKrwmn2Ojnmec3KCAbFwynyTHPxE2PpHlVhQhvb2Az" +
		"w2FeLGAw1btiItcvLDrS3cDI3TfQNaa8L2MX3Zfr2yBv9UUS4MfS2pZQ42" +
		"Czze7PMRk6LrWh0HA+SdBUG6XeXDHcvXH3rH4GxJHuDhALCgNabFYwuXysXdGP="
	cred := sts.Credentials{
		AccessKeyId:     &[]string{"AHENVMSKIRUEQNFHGZTA"}[0],
		SecretAccessKey: &[]string{"ZcqCQl34NF8PtXHSdbBk3mZze1plNNSWqnmsz523"}[0],
		SessionToken:    &st,
		Expiration:      &t,
	}
	return &cred
}

func getFakeAssumedRoleUser() *sts.AssumedRoleUser {
	aru := sts.AssumedRoleUser{
		Arn:           &[]string{"arn:aws:sts::123456789321:assumed-role/bu-readonly/212555555"}[0],
		AssumedRoleId: &[]string{"AROEIQPVJAEI7JWAN6FXW:212555555"}[0],
	}
	return &aru
}

type mockSTSClient struct {
	stsiface.STSAPI
	SVCErr error
}

func (m *mockSTSClient) GetCallerIdentity(input *sts.GetCallerIdentityInput) (output *sts.GetCallerIdentityOutput, err error) {
	if m.SVCErr != nil {
		return output, m.SVCErr
	}
	o := sts.GetCallerIdentityOutput{
		Account: &[]string{"123456789654"}[0],
		Arn:     &[]string{"arn:aws:sts::123456789654:assumed-role/oo/cool-dude"}[0],
		UserId:  &[]string{"AROWPVJQMNDGYETTAV5EO:cool-dude"}[0],
	}
	output = &o
	return output, err
}

func (m *mockSTSClient) AssumeRoleWithSAML(input *sts.AssumeRoleWithSAMLInput) (output *sts.AssumeRoleWithSAMLOutput, err error) {
	if m.SVCErr != nil {
		return output, m.SVCErr
	}

	aru := getFakeAssumedRoleUser()
	o := sts.AssumeRoleWithSAMLOutput{
		AssumedRoleUser: aru,
		Credentials:     getFakeCreds(),
		Issuer:          &[]string{"cmfssprd"}[0],
		Audience:        &[]string{"https://signin.aws.amazon.com/saml"}[0],
		Subject:         &[]string{"dudette@fake.com"}[0],
		SubjectType:     &[]string{"urn:oasis:names:tc:SAML:2.0:attrname-format:persistent"}[0],
	}
	output = &o
	return output, err
}

func (m *mockSTSClient) AssumeRole(input *sts.AssumeRoleInput) (output *sts.AssumeRoleOutput, err error) {
	if m.SVCErr != nil {
		return output, m.SVCErr
	}
	aru := getFakeAssumedRoleUser()
	o := sts.AssumeRoleOutput{
		AssumedRoleUser: aru,
		Credentials:     getFakeCreds(),
	}
	output = &o
	return output, err
}

func TestAssumeSAMLRoleWithSession(t *testing.T) {
	initLog()
	cases := []struct {
		mockSTSClientErr error
		result           *sts.Credentials
		principalArn     *string
		roleArn          *string
		roleSessionName  *string
		assertion        *string
		duration         *int64
	}{
		{
			principalArn:    &[]string{"arn:aws:iam::987654321654:saml-provider/oo-saml-for-aws-mfa"}[0],
			roleArn:         &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName: &[]string{"212555555"}[0],
			assertion:       &[]string{"somereallylongstring"}[0],
			duration:        &[]int64{9600}[0],
			result:          getFakeCreds(),
		},
		{
			principalArn:     &[]string{"arn:aws:iam::987654321654:saml-provider/oo-saml-for-aws-mfa"}[0],
			roleArn:          &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName:  &[]string{"212555555"}[0],
			assertion:        &[]string{"somereallylongstring"}[0],
			duration:         &[]int64{9600}[0],
			mockSTSClientErr: errors.New("whoa DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining or something bro"),
			result:           nil,
		},
		{
			principalArn:     &[]string{"arn:aws:iam::987654321654:saml-provider/oo-saml-for-aws-mfa"}[0],
			roleArn:          &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName:  &[]string{"212555555"}[0],
			assertion:        &[]string{"somereallylongstring"}[0],
			mockSTSClientErr: errors.New("we want some sort of nil pointer error for missing duration"),
			result:           nil,
		},
		{
			roleSessionName:  &[]string{"212555555"}[0],
			assertion:        &[]string{"somereallylongstring"}[0],
			duration:         &[]int64{9600}[0],
			mockSTSClientErr: errors.New("we want some sort of nil pointer error for missing stuff"),
			result:           nil,
		},
	}

	for i, c := range cases {
		mockSTSClient := &mockSTSClient{
			SVCErr: c.mockSTSClientErr,
		}
		fmt.Println("test case: ", i)
		result, err := assumeSAMLRoleWithSession(
			c.principalArn,
			c.roleArn,
			c.roleSessionName,
			c.assertion,
			c.duration,
			mockSTSClient,
		)
		if err != nil {
			if c.mockSTSClientErr == nil {
				t.Errorf("unexpected error: expected nil but got '%s'", err.Error())
			}
		}
		if result != nil && c.result != nil {
			if *result.AccessKeyId != *c.result.AccessKeyId {
				t.Errorf("unexpected result: want '%s', got '%s'\n", *result.AccessKeyId, *c.result.AccessKeyId)
			}
		} else if result != nil && c.result == nil {
			t.Error("unexpected result: expected result is nil but result is not")
		} else if result == nil && c.result != nil {
			t.Error("unexpected result: expected result is not nil but result is")
		}
	}
}

func TestAssumeRoleWithClient(t *testing.T) {
	initLog()
	cases := []struct {
		mockSTSClientErr error
		result           *sts.Credentials
		roleArn          *string
		roleSessionName  *string
		duration         *int64
	}{
		{
			// happy path
			roleArn:         &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName: &[]string{"212555555"}[0],
			duration:        &[]int64{3600}[0],
			result:          getFakeCreds(),
		},
		{
			// make sure it's handling duration exceeds error aws sometimes throws
			roleArn:          &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName:  &[]string{"212555555"}[0],
			duration:         &[]int64{9600}[0],
			mockSTSClientErr: errors.New("whoa DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining or something bro"),
			result:           nil,
		},
		{
			// detect some nil pointer nonsense to avoid runtime panics
			roleArn:          &[]string{"arn:aws:iam::987654321654:role/oo/cool-role"}[0],
			roleSessionName:  &[]string{"212555555"}[0],
			mockSTSClientErr: errors.New("we want some sort of nil pointer error for missing duration"),
			result:           nil,
		},
		{
			roleSessionName:  &[]string{"212555555"}[0],
			mockSTSClientErr: errors.New("we want some sort of nil pointer error for missing stuff"),
			result:           nil,
		},
	}

	for i, c := range cases {
		mockSTSClient := &mockSTSClient{
			SVCErr: c.mockSTSClientErr,
		}
		fmt.Println("test case: ", i)
		result, err := assumeRoleWithClient(
			c.roleArn,
			c.roleSessionName,
			c.duration,
			mockSTSClient,
		)
		if err != nil {
			if c.mockSTSClientErr == nil {
				t.Errorf("unexpected error: expected nil but got '%s'", err.Error())
			}
		}
		if result != nil && c.result != nil {
			if *result.AccessKeyId != *c.result.AccessKeyId {
				t.Errorf("unexpected result: want '%s', got '%s'\n", *result.AccessKeyId, *c.result.AccessKeyId)
			}
		} else if result != nil && c.result == nil {
			t.Error("unexpected result: expected result is nil but result is not")
		} else if result == nil && c.result != nil {
			t.Error("unexpected result: expected result is not nil but result is")
		}
	}
}

func TestGenerateRoleSessionName(t *testing.T) {
	initLog()
	cases := []struct {
		mockSTSClientErr error
		result           string
	}{
		{
			// happy path - prefix principal with gossamer
			result: "gossamer-cool-dude",
		},
		{
			// happy path
			mockSTSClientErr: errors.New("want this to blank out to gossamer in case of an error"),
			result:           "gossamer",
		},
	}

	for i, c := range cases {
		mockSTSClient := &mockSTSClient{
			SVCErr: c.mockSTSClientErr,
		}
		fmt.Println("test case: ", i)
		result := generateRoleSessionName(
			mockSTSClient,
		)
		if result != c.result {
			t.Errorf("unexpected result: want '%s', got '%s'\n", result, c.result)
		}
	}
}
