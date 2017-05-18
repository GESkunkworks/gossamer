package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

func writeBufferToFile(filename string, b *bytes.Buffer) error {
	err := ioutil.WriteFile(filename, b.Bytes(), 0644)
	return err
}

func genTestArnsJSON() (*bytes.Buffer, error) {
	seed := `{"Roles": [{"RoleArn": "arn:aws:iam::123456789101:role/prod-role",
		"AccountName": "prod-account"}, {"RoleArn": "arn:aws:iam::110987654321:role/dev-role",
		"AccountName": "dev-account"}]}`
	var b bytes.Buffer
	_, err := b.WriteString(seed)
	if err != nil {
		fmt.Println("error: ", err)
		return &b, err
	}
	return &b, err
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
	accounts, err := loadArnsFile(testRoleFileName)
	if err != nil {
		t.Errorf("Error loading file: %s", err)
	}
	if (len(accounts) < 2) || len(accounts) > 2 {
		t.Errorf("Number of arns loaded incorrect, got: %d, want: %d.", len(accounts), 2)
	}
}
