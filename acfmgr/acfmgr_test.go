package acfmgr

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

const baseCredFile string = `
[testing]
foo
bar

[newentry]
bar
foo

`

const expectedResult string = `
[testing]
foo
bar

[newentry]
bar
foo

[acfmgrtest]
my
test
here
`

const expectedResultDeletionEnd string = `
[testing]
foo
bar

`

const expectedResultDeletionMiddle string = `
[newentry]
bar
foo

`

func writeBaseFile(filename string) error {
	var b bytes.Buffer
	_, err := b.WriteString(baseCredFile)
	err = ioutil.WriteFile(filename, b.Bytes(), 0644)
	return err
}

func TestModifyEntry(t *testing.T) {
	filename := "./acfmgr_credfile_test.txt"
	err := writeBaseFile(filename)
	if err != nil {
		t.Errorf("Error making basefile: %s", err)
	}
	sess, err := NewCredFileSession(filename)
	if err != nil {
		t.Errorf("Error making credfile session: %s", err)
	}
	entryName := "[acfmgrtest]"
	entryContents := []string{"my", "test", "here"}
	sess.NewEntry(entryName, entryContents)
	err = sess.AssertEntries()
	if err != nil {
		t.Errorf("Error asserting entries: %s", err)
	}
	fullContents, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("Error reading file: %s", err)
	}
	got := string(fullContents)
	if got != expectedResult {
		t.Errorf("Result not expected. Got: %s", got)
	}
	defer os.Remove(filename)
}

func TestDeleteEntryAtEnd(t *testing.T) {
	filename := "./acfmgr_credfile_test1.txt"
	err := writeBaseFile(filename)
	if err != nil {
		t.Errorf("Error making basefile: %s", err)
	}
	sess, err := NewCredFileSession(filename)
	if err != nil {
		t.Errorf("Error making credfile session: %s", err)
	}
	entryName := "[newentry]"
	entryContents := []string{"whocares"}
	sess.NewEntry(entryName, entryContents)
	err = sess.DeleteEntries()
	if err != nil {
		t.Errorf("Error deleting entries: %s", err)
	}
	fullContents, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("Error reading file: %s", err)
	}
	got := string(fullContents)
	if got != expectedResultDeletionEnd {
		t.Errorf("Result not expected. Got: %s", got)
	}
	defer os.Remove(filename)
}

func TestDeleteEntryInMiddle(t *testing.T) {
	filename := "./acfmgr_credfile_test2.txt"
	err := writeBaseFile(filename)
	if err != nil {
		t.Errorf("Error making basefile: %s", err)
	}
	sess, err := NewCredFileSession(filename)
	if err != nil {
		t.Errorf("Error making credfile session: %s", err)
	}
	entryName := "[testing]"
	entryContents := []string{"whocares"}
	sess.NewEntry(entryName, entryContents)
	err = sess.DeleteEntries()
	if err != nil {
		t.Errorf("Error deleting entries: %s", err)
	}
	fullContents, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("Error reading file: %s", err)
	}
	got := string(fullContents)
	if got != expectedResultDeletionMiddle {
		t.Errorf("Result not expected. Got: %s", got)
	}
	defer os.Remove(filename)
}
