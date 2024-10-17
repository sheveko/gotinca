package cmd

import "testing"

func TestCheckDomain(t *testing.T) {
	var mustWorks = []string{
		"foo.bar",
		"*.foo.bar",
		"bar",
	}

	var mustNotWorks = []string{
		"f_oo.bar",
		"Foo.bar",
		"foo.*.bar",
		".foo.bar",
		"foo.bar.",
	}

	for _, mustNotWork := range mustNotWorks {
		err := checkDomain(mustNotWork)
		if err == nil {
			t.Fatalf("Test unexpectedly works for domain: %s", mustNotWork)
		}
	}

	for _, mustWork := range mustWorks {
		err := checkDomain(mustWork)
		if err != nil {
			t.Fatal(err)
		}
	}

}
