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
	Agents       []Agent  `json:"agents"`
	AWSProfiles  []string `json:"aws_profiles"`
	KubeContexts []string `json:"kube_contexts"`
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
	configProfiles, err := readAWSConfigProfiles(filepath.Join(home, ".aws", "config"), true)
	if err != nil {
		return Result{}, err
	}
	credentialProfiles, err := readAWSConfigProfiles(filepath.Join(home, ".aws", "credentials"), false)
	if err != nil {
		return Result{}, err
	}
	profiles := uniqueSorted(append(configProfiles, credentialProfiles...))

	kubePaths := []string{filepath.Join(home, ".kube", "config")}
	if configured := strings.TrimSpace(os.Getenv("KUBECONFIG")); configured != "" {
		kubePaths = filepath.SplitList(configured)
	}
	contexts := make([]string, 0)
	for _, path := range kubePaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		found, err := readKubeContextNames(path)
		if err != nil {
			return Result{}, err
		}
		contexts = append(contexts, found...)
	}
	return Result{Agents: agents, AWSProfiles: profiles, KubeContexts: uniqueSorted(contexts)}, nil
}

func readAWSConfigProfiles(path string, configFile bool) ([]string, error) {
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
		if configFile && strings.HasPrefix(section, "profile ") {
			name := strings.TrimSpace(strings.TrimPrefix(section, "profile "))
			if name != "" {
				profiles = append(profiles, name)
			}
		} else if !configFile && !strings.ContainsAny(section, " \t") {
			profiles = append(profiles, section)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read AWS config: %w", err)
	}
	return uniqueSorted(profiles), nil
}

func readKubeContextNames(path string) ([]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open kubeconfig: %w", err)
	}
	defer file.Close()

	contexts := make([]string, 0)
	inContexts := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			inContexts = trimmed == "contexts:"
			continue
		}
		if !inContexts {
			continue
		}
		candidate := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if !strings.HasPrefix(candidate, "name:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(candidate, "name:"))
		name = strings.Trim(name, "\"'")
		if name != "" {
			contexts = append(contexts, name)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}
	return uniqueSorted(contexts), nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
