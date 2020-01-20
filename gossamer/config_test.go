package gossamer

import (
	"fmt"
	"testing"
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

