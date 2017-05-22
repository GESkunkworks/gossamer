// Package acfmgr is a package to manage entries in an AWS credentials file
//
// Sample AWS creds file format:
//   [default]
//   output = json
//   region = us-east-1
//   aws_access_key_id = QOWIASOVNALKNVCIE
//   aws_secret_access_key = zgylMqe64havoaoinweofnviUHqQKYHMGzFMA8CI
//   aws_session_token = FQoDYXdzEGYaDNYfEnCsHW/8rG3zpiKwAfS8T...
//
//   [dev-default]
//   output = json
//   region = us-west-1
//   aws_access_key_id = QOWIAADFEGKNVCIE
//   aws_secret_access_key = zgylMqaoivnawoeenweofnviUHqQKYHMGzFMA8CI
//   aws_session_token = FQoDYXdzEGYaDNYfEnCsanv;oaiwe\iKwAfS8T...
//
// Adding and removing entries manually is a pain so this package was created
// to assist in programattically adding them once you have sessions built
// from the Golang AWS SDK.
//
// Calling AssertEntries will delete all entries of that name and only rewrite
// the given entry with the given contents.
//
// Calling DeleteEntries will delete all entries of that name.
//
// Sample
//
//  c, err := acfmgr.NewCredFileSession("~/.aws/credentials")
//  check(err)
//  c.NewEntry("[dev-account-1]", []string{"output = json", "region = us-east-1", "...", ""})
//  c.NewEntry("[dev-account-2]", []string{"output = json", "region = us-west-1", "...", ""})
//  err = c.AssertEntries()
// Yields:
//   [dev-account-1]
//   output = json
//   region = us-east-1
//   ...
//
//   [dev-account-2]
//   output = json
//   region = us-west-1
//   ...
//
// While:
//  c, err := acfmgr.NewCredFileSession("~/.aws/credentials")
//  check(err)
//  c.NewEntry("[dev-account-2]", []string{"output = json", "region = us-west-1", "...", ""})
//  err = c.DeleteEntries()
// Yields:
//   [dev-account-2]
//   output = json
//   region = us-west-1
//   ...
//
package acfmgr

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

// NewCredFileSession creates a new interactive credentials file
// session. Needs target filename and returns CredFile obj and err.
func NewCredFileSession(filename string) (*CredFile, error) {
	cf := CredFile{filename: filename,
		currBuff: new(bytes.Buffer),
		reSep:    regexp.MustCompile(`\[.*\]`),
	}
	err := cf.loadFile()
	if err != nil {
		return &cf, err
	}
	return &cf, err
}

// CredFile should be built with the exported
// NewCredFileSession function.
type CredFile struct {
	filename string
	ents     []*credEntry
	currBuff *bytes.Buffer
	reSep    *regexp.Regexp // regex cred anchor separator e.g. "[\w*]"
}

type credEntry struct {
	name     string
	contents []string
}

// NewEntry adds a new credentials entry to the queue
// to be written or deleted with the AssertEntries or
// DeleteEntries method.
func (c *CredFile) NewEntry(entryName string, entryContents []string) {
	e := credEntry{name: entryName, contents: entryContents}
	c.ents = append(c.ents, &e)
}

// AssertEntries loops through all of the credEntry objs
// attached to CredFile obj and makes sure there is an
// occurrence with the credEntry.name and contents.
// Existing entries of the same name with different
// contents will be clobbered.
func (c *CredFile) AssertEntries() (err error) {
	for _, e := range c.ents {
		err = c.modifyEntry(true, e)
		if err != nil {
			return err
		}
	}
	return err
}

// DeleteEntries loops through all of the credEntry
// objs attached to CredFile obj and makes sure entries
// with the same credEntry.name are removed. Will remove
// ALL entries with the same name.
func (c *CredFile) DeleteEntries() (err error) {
	for _, e := range c.ents {
		err = c.modifyEntry(false, e)
		if err != nil {
			return err
		}
	}
	return err
}

func (e *credEntry) appendToList(lister []string) []string {
	lister = append(lister, e.name)
	for _, line := range e.contents {
		lister = append(lister, line)
	}
	return lister
}

func (c *CredFile) loadFile() error {
	if !c.fileExists() {
		_, err := c.createFile()
		if err != nil {
			panic(err)
		}
	}
	f, err := os.OpenFile(c.filename, os.O_RDONLY, os.ModeAppend)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		c.currBuff.WriteString(scanner.Text() + "\n")
	}
	return err
}

func (c *CredFile) writeBufferToFile() error {
	err := ioutil.WriteFile(c.filename, c.currBuff.Bytes(), 0644)
	return err
}

// indexOf find the index of a value in an []int
func indexOf(s []int, e int) (index int) {
	for index, a := range s {
		if a == e {
			return index
		}
	}
	return -1
}

func (c *CredFile) removeEntry(data []string, anchors []int, entry *credEntry) []string {
	ignoring := false
	ignoreUntil := 0
	var newLines []string
	for i, line := range data {
		if line == entry.name {
			currIndex := indexOf(anchors, i)
			if (currIndex + 1) >= len(anchors) {
				// this means it's at EOF
				ignoreUntil = len(data)
			} else {
				ignoreUntil = anchors[currIndex+1]
			}

			ignoring = true
		}
		if !(ignoring && i < ignoreUntil) {
			newLines = append(newLines, line)
		}
	}
	return newLines
}

// EnsureEntryExists makes sure that the attached Ent
// entry exists.
func (c *CredFile) modifyEntry(replace bool, entry *credEntry) (err error) {
	found := false
	// read buffer into []string
	var lines []string
	scanner := bufio.NewScanner(c.currBuff)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	// search for entry
	var anchors []int
	for i, line := range lines {
		reMatch := c.reSep.FindAllString(line, -1)
		if reMatch != nil {
			anchors = append(anchors, i)
		}
		if line == entry.name {
			found = true
		}
	}
	switch {
	case found && replace:
		lines = c.removeEntry(lines, anchors, entry)
		// make the credEntry append itself to the results
		lines = entry.appendToList(lines)
	case found && !replace:
		lines = c.removeEntry(lines, anchors, entry)
	case !found && !replace:
		// do nothing
	case !found && replace:
		lines = entry.appendToList(lines)
	}
	// now write []string to buffer adding newlines
	for _, line := range lines {
		c.currBuff.WriteString(fmt.Sprintf("%s\n", line))
	}
	err = c.writeBufferToFile()
	return err
}

func (c *CredFile) fileExists() bool {
	_, err := os.Stat(c.filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func (c *CredFile) createFile() (bool, error) {
	_, err := os.Create(c.filename)
	if err != nil {
		return false, err
	}
	return true, err
}
