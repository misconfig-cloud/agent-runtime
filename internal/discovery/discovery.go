package discovery

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Agent struct {
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Available  bool   `json:"available"`
}

type Result struct {
	Agents      []Agent  `json:"agents"`
	AWSProfiles []string `json:"aws_profiles"`
}

func Scan(home string, lookup func(string) (string, error)) (Result, error) {
	if strings.TrimSpace(home) == "" {
		return Result{}, errors.New("home directory is required")
	}
	if lookup == nil {
		lookup = exec.LookPath
	}
	agents := make([]Agent, 0, 2)
	for _, name := range []string{"codex", "claude"} {
		path, err := lookup(name)
		agents = append(agents, Agent{Name: name, Executable: path, Available: err == nil})
	}
	profiles, err := readAWSConfigProfiles(filepath.Join(home, ".aws", "config"))
	if err != nil {
		return Result{}, err
	}
	return Result{Agents: agents, AWSProfiles: profiles}, nil
}

func readAWSConfigProfiles(path string) ([]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open AWS config: %w", err)
	}
	defer file.Close()

	profiles := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}
		section := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
		if section == "default" {
			profiles = append(profiles, "default")
			continue
		}
		if strings.HasPrefix(section, "profile ") {
			name := strings.TrimSpace(strings.TrimPrefix(section, "profile "))
			if name != "" {
				profiles = append(profiles, name)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read AWS config: %w", err)
	}
	sort.Strings(profiles)
	return profiles, nil
}
