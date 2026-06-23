package main

import (
	"path/filepath"
	"testing"
)

func dbPath() string  { return findUp(filepath.Join("dvmobile", "cognis_vulndb.jsonl.gz")) }
func catPath() string { return findUp(filepath.Join("ports", "challenges.json")) }

func TestLoadChallenges(t *testing.T) {
	cs, err := LoadChallenges(catPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 4 {
		t.Fatalf("want 4 challenges, got %d", len(cs))
	}
}

func TestLog4jResolves(t *testing.T) {
	hits, err := ByCVE(dbPath(), "CVE-2021-44228")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) < 1 {
		t.Fatal("CVE-2021-44228 (log4j) should resolve in the bundled DB")
	}
}

func TestUnknownCVEEmpty(t *testing.T) {
	hits, _ := ByCVE(dbPath(), "CVE-0000-00000")
	if len(hits) != 0 {
		t.Fatalf("expected no hits, got %d", len(hits))
	}
}

func TestEveryChallengeCVEResolves(t *testing.T) {
	cs, err := LoadChallenges(catPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		for _, cve := range c.RealWorldCVEs {
			hits, _ := ByCVE(dbPath(), cve)
			if len(hits) == 0 {
				t.Errorf("%s: %s did not resolve offline", c.ID, cve)
			}
		}
	}
}
