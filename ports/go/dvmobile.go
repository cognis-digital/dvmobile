// Command dvmobile is a Go port of the dvmobile CLI surface. It lists the MASVS
// challenges and resolves CVE/GHSA identifiers against the bundled, offline OSV
// database (cognis_vulndb.jsonl.gz, ~262k real records). Offline only — it never
// touches the network.
//
//	dvmobile challenges [--cves]
//	dvmobile cve CVE-2021-44228
//	dvmobile enrich [challenge-id]
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Challenge mirrors one row of ports/challenges.json.
type Challenge struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	Difficulty    string   `json:"difficulty"`
	MASVS         string   `json:"masvs"`
	CWE           string   `json:"cwe"`
	Hint          string   `json:"hint"`
	RealWorldCVEs []string `json:"real_world_cves"`
}

// VulnRecord is the compact OSV record stored in the bundled DB.
type VulnRecord struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Ecosystem string   `json:"ecosystem"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	Packages  []string `json:"packages"`
}

// findUp walks up from the executable/source dir to locate a relative asset.
func findUp(rel string) string {
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return rel
}

// LoadChallenges reads the shared catalog JSON.
func LoadChallenges(path string) ([]Challenge, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cs []Challenge
	return cs, json.Unmarshal(b, &cs)
}

// ByCVE streams the gz database and returns records matching a CVE/GHSA id.
func ByCVE(dbPath, cve string) ([]VulnRecord, error) {
	want := strings.ToUpper(strings.TrimSpace(cve))
	var out []VulnRecord
	if want == "" {
		return out, nil
	}
	f, err := os.Open(dbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r VulnRecord
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		ids := append([]string{r.ID}, r.Aliases...)
		for _, id := range ids {
			if strings.ToUpper(id) == want {
				out = append(out, r)
				break
			}
		}
	}
	return out, sc.Err()
}

func cveOf(r VulnRecord) string {
	for _, a := range r.Aliases {
		if strings.HasPrefix(a, "CVE") {
			return a
		}
	}
	return r.ID
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

func run(args []string) int {
	catalog := findUp(filepath.Join("ports", "challenges.json"))
	db := findUp(filepath.Join("dvmobile", "cognis_vulndb.jsonl.gz"))
	if len(args) == 0 {
		fmt.Println("usage: dvmobile (challenges [--cves] | cve <id> | enrich [id])")
		return 1
	}
	switch args[0] {
	case "challenges":
		cs, err := LoadChallenges(catalog)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		showCVEs := len(args) > 1 && args[1] == "--cves"
		for _, c := range cs {
			fmt.Printf("%s [%s] %s %s\n", pad(c.ID, 16), pad(c.Difficulty, 6), pad(c.MASVS, 14), c.Title)
			if showCVEs && len(c.RealWorldCVEs) > 0 {
				fmt.Printf("                 %s  real-world: %s\n", c.CWE, strings.Join(c.RealWorldCVEs, ", "))
			}
		}
		return 0
	case "cve":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: dvmobile cve <id>")
			return 2
		}
		hits, err := ByCVE(db, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(hits) == 0 {
			fmt.Printf("no match for %s in the bundled offline DB\n", args[1])
			return 1
		}
		for _, r := range hits {
			fmt.Printf("%s  [%s]  %s\n", r.ID, r.Ecosystem, strings.Join(r.Aliases, ", "))
			fmt.Printf("  %s\n", r.Summary)
		}
		return 0
	case "enrich":
		cs, err := LoadChallenges(catalog)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		var sel []Challenge
		if len(args) > 1 {
			for _, c := range cs {
				if c.ID == args[1] {
					sel = append(sel, c)
				}
			}
			if len(sel) == 0 {
				fmt.Printf("unknown challenge: %s\n", args[1])
				return 2
			}
		} else {
			sel = cs
		}
		for _, c := range sel {
			resolved := 0
			var matches []VulnRecord
			for _, cve := range c.RealWorldCVEs {
				hits, _ := ByCVE(db, cve)
				if len(hits) > 0 {
					resolved++
					matches = append(matches, hits[0])
				}
			}
			fmt.Printf("%s  %s  %s  (%d CVEs resolved offline)\n", c.ID, c.MASVS, c.CWE, resolved)
			for _, m := range matches {
				s := m.Summary
				if len(s) > 70 {
					s = s[:70]
				}
				fmt.Printf("  %s %s\n", pad(cveOf(m), 18), s)
			}
		}
		return 0
	}
	fmt.Println("usage: dvmobile (challenges [--cves] | cve <id> | enrich [id])")
	return 1
}

func main() { os.Exit(run(os.Args[1:])) }
