package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/credentialruntime"
	"github.com/misconfig-cloud/agent-runtime/internal/discovery"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/enforcement"
	"github.com/misconfig-cloud/agent-runtime/internal/hook"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
	"github.com/misconfig-cloud/agent-runtime/internal/policy"
	"github.com/misconfig-cloud/agent-runtime/internal/spool"
)

const defaultControlURL = "https://sessions.misconfig.cloud"

type Control interface {
	Enroll(context.Context, string, string, string, string, string) (controlclient.Enrollment, error)
	CreateDeviceAuthorization(context.Context, string) (controlclient.DeviceAuthorizationStart, error)
	ExchangeDeviceAuthorization(context.Context, string) (controlclient.DeviceAuthorizationExchange, error)
	CreateProfile(context.Context, controlclient.CreateProfileRequest) (domain.SessionProfile, string, error)
	CreateProfileSuccessor(context.Context, string, controlclient.CreateProfileSuccessorRequest) (controlclient.ProfileSuccessor, error)
	Profiles(context.Context) ([]domain.SessionProfile, error)
	CredentialProviders(context.Context) ([]controlclient.CredentialProvider, error)
	CreateCredentialConnection(context.Context, controlclient.CreateCredentialConnectionRequest) (controlclient.PreparedCredentialConnection, error)
	CredentialConnections(context.Context) ([]controlclient.CredentialConnection, error)
	VerifyCredentialConnection(context.Context, string) (controlclient.CredentialConnection, error)
	RevokeCredentialConnection(context.Context, string) error
	CredentialLease(context.Context, string, string) (controlclient.CredentialMaterial, error)
	StartSession(context.Context, domain.SessionProfile) (domain.AgentSession, error)
	Session(context.Context, string) (domain.AgentSession, error)
	Sessions(context.Context) ([]domain.AgentSession, error)
	Policy(context.Context, string) (policy.SignedBundle, error)
	Stop(context.Context, string, string) error
	PutReceipt(context.Context, spool.Receipt) error
}

type CommandRunner func(context.Context, string, []string, string, []string, io.Reader, io.Writer, io.Writer) error

type App struct {
	In              io.Reader
	Out             io.Writer
	Err             io.Writer
	Version         string
	StateRoot       string
	FileTokens      bool
	Getenv          func(string) string
	Executable      func() (string, error)
	LookPath        func(string) (string, error)
	NewControl      func(string, string, string) Control
	RunCommand      CommandRunner
	Now             func() time.Time
	UserHomeDir     func() (string, error)
	CurrentDir      func() (string, error)
	Hostname        func() (string, error)
	OpenURL         func(string) error
	RefreshInterval time.Duration
	// CredentialAdapters are trusted, compiled runtime adapters. The core does
	// not discover or execute provider plugins from the filesystem.
	CredentialAdapters []credentialruntime.Adapter
}

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }
func (e exitError) ExitCode() int { return e.code }

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
}

func (a *App) Run(ctx context.Context, args []string) error {
	a.defaults()
	if len(args) == 0 {
		a.usage()
		return exitError{code: 2, err: errors.New("command is required")}
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(a.Out, "misconfig %s\n", a.Version)
		return nil
	case "doctor":
		return a.doctor()
	case "setup":
		return a.setup(ctx, args[1:])
	case "profile":
		return a.profile(ctx, args[1:])
	case "run":
		return a.runSession(ctx, args[1:])
	case "credential":
		return a.credential(ctx, args[1:])
	case "status":
		return a.status(ctx, args[1:])
	case "sync":
		return a.sync(ctx, args[1:])
	case "uninstall":
		return a.uninstall(ctx, args[1:])
	case "hook":
		return a.hook(ctx, args[1:])
	default:
		a.usage()
		return exitError{code: 2, err: fmt.Errorf("unknown command %q", args[0])}
	}
}

func (a *App) defaults() {
	if a.In == nil {
		a.In = os.Stdin
	}
	if a.Out == nil {
		a.Out = os.Stdout
	}
	if a.Err == nil {
		a.Err = os.Stderr
	}
	if a.Version == "" {
		a.Version = "dev"
	}
	if a.Getenv == nil {
		a.Getenv = os.Getenv
	}
	if a.Executable == nil {
		a.Executable = os.Executable
	}
	if a.LookPath == nil {
		a.LookPath = exec.LookPath
	}
	if a.NewControl == nil {
		a.NewControl = func(baseURL, tenantID, token string) Control {
			return controlclient.Client{BaseURL: baseURL, TenantID: tenantID, Token: token}
		}
	}
	if a.RunCommand == nil {
		a.RunCommand = runCommand
	}
	if a.Now == nil {
		a.Now = func() time.Time { return time.Now().UTC() }
	}
	if a.UserHomeDir == nil {
		a.UserHomeDir = os.UserHomeDir
	}
	if a.CurrentDir == nil {
		a.CurrentDir = os.Getwd
	}
	if a.Hostname == nil {
		a.Hostname = os.Hostname
	}
	if a.OpenURL == nil {
		a.OpenURL = openBrowser
	}
	if a.RefreshInterval <= 0 {
		a.RefreshInterval = 5 * time.Second
	}
}

func (a *App) store() (localstate.Store, error) {
	root := a.StateRoot
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = localstate.DefaultRoot()
		if err != nil {
			return localstate.Store{}, err
		}
	}
	return localstate.Store{Root: filepath.Clean(root), FileTokens: a.FileTokens}, nil
}

func (a *App) authenticated() (localstate.Store, localstate.Config, Control, error) {
	store, err := a.store()
	if err != nil {
		return store, localstate.Config{}, nil, err
	}
	config, err := store.LoadConfig()
	if err != nil {
		return store, config, nil, fmt.Errorf("load enrollment: %w", err)
	}
	token, err := store.DeviceToken(config.DeviceID)
	if err != nil {
		return store, config, nil, fmt.Errorf("load device credential: %w", err)
	}
	return store, config, a.NewControl(config.ControlURL, config.TenantID, token), nil
}

func (a *App) doctor() error {
	home, err := a.UserHomeDir()
	if err != nil {
		return err
	}
	result, err := discovery.Scan(filepath.Clean(home), nil)
	if err != nil {
		return err
	}
	return writeJSON(a.Out, result)
}

func (a *App) setup(ctx context.Context, args []string) error {
	flags := a.flags("setup")
	controlURL := flags.String("control", defaultControlURL, "control-plane URL")
	tenantID := flags.String("tenant", "", "tenant ID")
	tenantName := flags.String("tenant-name", "", "tenant name")
	actorID := flags.String("actor", "", "actor identity")
	deviceName := flags.String("device", "", "device name")
	tokenFile := flags.String("token-file", "", "enrollment token file, or - for stdin")
	yes := flags.Bool("yes", false, "apply the displayed setup changes")
	noOpen := flags.Bool("no-open", false, "print the browser link without opening it")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if flags.NArg() != 0 {
		return exitError{code: 2, err: errors.New("setup does not accept positional arguments")}
	}
	if *deviceName == "" {
		name, err := a.Hostname()
		if err != nil {
			return fmt.Errorf("discover device name: %w", err)
		}
		*deviceName = name
	}
	store, err := a.store()
	if err != nil {
		return err
	}
	if _, err := store.LoadConfig(); err == nil {
		return errors.New("this device is already enrolled; run `misconfig uninstall --yes` before replacing its identity")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing enrollment: %w", err)
	}
	legacy := strings.TrimSpace(*tenantID) != "" || strings.TrimSpace(*actorID) != "" || strings.TrimSpace(*tokenFile) != "" || strings.TrimSpace(a.Getenv("MISCONFIG_ENROLLMENT_TOKEN")) != ""
	a.setupPreview(store, *controlURL, *deviceName, legacy)
	if !*yes {
		approved, err := a.confirmSetup()
		if err != nil {
			return err
		}
		if !approved {
			fmt.Fprintln(a.Out, "Setup cancelled. No files, credentials, or agent configuration were changed.")
			return nil
		}
	}
	client := a.NewControl(*controlURL, "", "")
	var enrollment controlclient.Enrollment
	if legacy {
		if strings.TrimSpace(*tenantID) == "" || strings.TrimSpace(*actorID) == "" {
			return exitError{code: 2, err: errors.New("recovery enrollment requires both --tenant and --actor")}
		}
		if *tenantName == "" {
			*tenantName = *tenantID
		}
		token, err := a.enrollmentToken(*tokenFile)
		if err != nil {
			return err
		}
		enrollment, err = client.Enroll(ctx, token, *tenantID, *tenantName, *actorID, *deviceName)
		if err != nil {
			return fmt.Errorf("enroll device with recovery token: %w", err)
		}
	} else {
		start, err := client.CreateDeviceAuthorization(ctx, *deviceName)
		if err != nil {
			return fmt.Errorf("start browser device pairing: %w", err)
		}
		if start.DeviceCode == "" || start.UserCode == "" || start.VerificationURIComplete == "" {
			return errors.New("control plane returned an incomplete device authorization")
		}
		fmt.Fprintf(a.Out, "Approve this device in your browser.\n\n  Code: %s\n  Link: %s\n\n", start.UserCode, start.VerificationURIComplete)
		if !*noOpen {
			if err := a.OpenURL(start.VerificationURIComplete); err != nil {
				fmt.Fprintf(a.Err, "Browser could not be opened automatically: %v\n", err)
			}
		}
		deadline := a.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
		for {
			if !deadline.After(a.Now()) {
				return errors.New("device pairing expired before approval; run setup again")
			}
			exchange, err := client.ExchangeDeviceAuthorization(ctx, start.DeviceCode)
			if err != nil {
				return fmt.Errorf("complete browser device pairing: %w", err)
			}
			if exchange.State == "authorized" {
				enrollment = exchange.Enrollment
				break
			}
			if exchange.State != "pending" {
				return fmt.Errorf("control plane returned unknown device authorization state %q", exchange.State)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(a.RefreshInterval):
			}
		}
	}
	if enrollment.Device.ID == "" || enrollment.Device.TenantID == "" || enrollment.Device.ActorID == "" || enrollment.DeviceToken == "" || enrollment.PolicyKeyID == "" || enrollment.PolicyPublicKey == "" {
		return errors.New("control plane returned an incomplete enrollment")
	}
	if err := store.PutDeviceToken(enrollment.Device.ID, enrollment.DeviceToken); err != nil {
		return err
	}
	config := localstate.Config{
		ControlURL: *controlURL, TenantID: enrollment.Device.TenantID, ActorID: enrollment.Device.ActorID,
		DeviceID: enrollment.Device.ID, DeviceName: *deviceName,
		PolicyKeyID: enrollment.PolicyKeyID, PolicyPublicKey: enrollment.PolicyPublicKey,
	}
	if err := store.SaveConfig(config); err != nil {
		_ = store.DeleteDeviceToken(enrollment.Device.ID)
		return err
	}
	fmt.Fprintf(a.Out, "Device paired. %s is governed for tenant %s.\n", enrollment.Device.ID, enrollment.Device.TenantID)
	return nil
}

func (a *App) setupPreview(store localstate.Store, controlURL, deviceName string, recovery bool) {
	credentialBackend := "encrypted operating-system credential store"
	if a.FileTokens || runtime.GOOS != "darwin" {
		credentialBackend = filepath.Join(store.Root, "secrets", "<device-id>") + " (mode 0600)"
	}
	approval := "authenticated browser approval"
	if recovery {
		approval = "operator-issued recovery token"
	}
	fmt.Fprintf(a.Out, "Setup preview\n\n  Control plane: %s\n  Device: %s\n  State: %s\n  Device credential: %s\n  Authorization: %s\n  Codex configuration: unchanged\n  Claude configuration: unchanged\n  AWS and Kubernetes credentials: not read, copied, or uploaded\n\n", strings.TrimRight(controlURL, "/"), deviceName, filepath.Join(store.Root, "config.json"), credentialBackend, approval)
}

func (a *App) confirmSetup() (bool, error) {
	fmt.Fprint(a.Out, "Continue? [y/N] ")
	line, err := bufio.NewReader(a.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read setup confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func openBrowser(target string) error {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command, args = "open", []string{target}
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		command, args = "xdg-open", []string{target}
	}
	return exec.Command(command, args...).Start()
}

func (a *App) enrollmentToken(path string) (string, error) {
	var encoded []byte
	var err error
	switch {
	case path == "-":
		encoded, err = io.ReadAll(io.LimitReader(a.In, 64<<10))
	case strings.TrimSpace(path) != "":
		encoded, err = os.ReadFile(filepath.Clean(path))
	default:
		encoded = []byte(a.Getenv("MISCONFIG_ENROLLMENT_TOKEN"))
	}
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	token := strings.TrimSpace(string(encoded))
	if token == "" {
		return "", errors.New("enrollment token is required via --token-file, stdin, or MISCONFIG_ENROLLMENT_TOKEN")
	}
	return token, nil
}

func (a *App) profile(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return exitError{code: 2, err: errors.New("profile requires create or list")}
	}
	switch args[0] {
	case "create":
		return a.createProfile(ctx, args[1:])
	case "list":
		return a.listProfiles(ctx, args[1:])
	case "migrate":
		return a.migrateProfile(ctx, args[1:])
	default:
		return exitError{code: 2, err: fmt.Errorf("unknown profile command %q", args[0])}
	}
}

func (a *App) migrateProfile(ctx context.Context, args []string) error {
	flags := a.flags("profile migrate")
	profileReference := flags.String("profile", "", "legacy profile name or ID")
	ttl := flags.Int64("policy-ttl", 300, "successor signed policy TTL in seconds")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if *profileReference == "" && flags.NArg() == 1 {
		*profileReference = flags.Arg(0)
	} else if flags.NArg() != 0 || *profileReference == "" {
		return exitError{code: 2, err: errors.New("profile migrate requires --profile or one profile name or ID")}
	}
	if *ttl < 60 || *ttl > 86400 {
		return exitError{code: 2, err: errors.New("policy-ttl must be between 60 and 86400 seconds")}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	profiles, err := control.Profiles(ctx)
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	predecessor, err := selectProfile(profiles, *profileReference)
	if err != nil {
		return err
	}
	successor, err := control.CreateProfileSuccessor(ctx, predecessor.ID, controlclient.CreateProfileSuccessorRequest{
		AdapterRelease: string(predecessor.Agent) + "@" + a.Version, PolicyTTLSeconds: *ttl,
	})
	if err != nil {
		return fmt.Errorf("create profile successor: %w", err)
	}
	fmt.Fprintf(a.Out, "Created compatible successor %s (%s) for immutable profile %s. Run it with `misconfig run --profile %s`.\n", successor.Profile.Name, successor.Profile.ID, predecessor.ID, successor.Profile.ID)
	return nil
}

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*s = append(*s, value)
	return nil
}

func (a *App) createProfile(ctx context.Context, args []string) error {
	flags := a.flags("profile create")
	name := flags.String("name", "", "profile name")
	agent := flags.String("agent", "codex", "codex or claude")
	workspace := flags.String("workspace", "", "workspace directory")
	provider := flags.String("provider", "", "provider")
	account := flags.String("account", "", "provider account or cluster")
	enforcementLevel := flags.String("enforcement", string(domain.EnforcementHook), "enforcement level")
	credentialMode := flags.String("credential-mode", string(domain.CredentialAttach), "credential mode")
	credentialConnection := flags.String("credential-connection", "", "verified credential connection ID")
	credentialProviderRelease := flags.String("credential-provider-release", "", "immutable credential provider release")
	rulesPath := flags.String("rules", "", "JSON policy rules")
	ttl := flags.Int64("policy-ttl", 300, "signed policy TTL in seconds")
	var environments stringsFlag
	var resourcePrefixes stringsFlag
	flags.Var(&environments, "environment", "allowed environment; repeatable")
	flags.Var(&resourcePrefixes, "resource-prefix", "allowed resource prefix; repeatable")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if *name == "" && flags.NArg() == 1 {
		*name = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return exitError{code: 2, err: errors.New("provide one profile name or --name")}
	}
	if *workspace == "" {
		cwd, err := a.CurrentDir()
		if err != nil {
			return err
		}
		*workspace = cwd
	}
	absoluteWorkspace, err := filepath.Abs(*workspace)
	if err != nil {
		return fmt.Errorf("resolve workspace: %w", err)
	}
	info, err := os.Stat(absoluteWorkspace)
	if err != nil || !info.IsDir() {
		return exitError{code: 2, err: errors.New("workspace must be an existing directory")}
	}
	if len(environments) == 0 {
		environments = []string{"development"}
	}
	scope := domain.Scope{Provider: *provider, AccountRef: *account, Environments: environments, ResourcePrefixes: resourcePrefixes}
	if err := scope.Validate(); err != nil {
		return exitError{code: 2, err: fmt.Errorf("invalid scope: %w", err)}
	}
	agentKind := domain.AgentKind(*agent)
	if agentKind != domain.AgentCodex && agentKind != domain.AgentClaude {
		return exitError{code: 2, err: fmt.Errorf("unsupported agent %q", *agent)}
	}
	rules, err := readRules(*rulesPath)
	if err != nil {
		return exitError{code: 2, err: err}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	var credentialBinding *domain.CredentialBinding
	if domain.CredentialMode(*credentialMode) == domain.CredentialBrokered {
		credentialBinding = &domain.CredentialBinding{ConnectionID: strings.TrimSpace(*credentialConnection), ProviderRelease: strings.TrimSpace(*credentialProviderRelease)}
		if err := credentialBinding.Validate(); err != nil {
			return exitError{code: 2, err: fmt.Errorf("invalid credential binding: %w", err)}
		}
	} else if strings.TrimSpace(*credentialConnection) != "" || strings.TrimSpace(*credentialProviderRelease) != "" {
		return exitError{code: 2, err: errors.New("credential connection flags require --credential-mode brokered")}
	}
	profile, digest, err := control.CreateProfile(ctx, controlclient.CreateProfileRequest{
		Name: *name, Agent: *agent, Workspace: absoluteWorkspace, Scope: scope,
		Enforcement: domain.EnforcementLevel(*enforcementLevel), CredentialMode: domain.CredentialMode(*credentialMode),
		CredentialBinding: credentialBinding,
		AdapterRelease:    string(agentKind) + "@" + a.Version, Rules: rules, PolicyTTLSeconds: *ttl,
	})
	if err != nil {
		return fmt.Errorf("create profile: %w", err)
	}
	fmt.Fprintf(a.Out, "Created %s (%s), digest %s.\n", profile.Name, profile.ID, digest)
	return nil
}

func readRules(path string) ([]policy.Rule, error) {
	if strings.TrimSpace(path) == "" {
		return []policy.Rule{{
			ID: "misconfig.default.require-approval", Effect: policy.EffectApproval,
			Reason: "this safe default requires approval for every infrastructure action",
		}}, nil
	}
	encoded, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rules []policy.Rule
	if err := json.Unmarshal(encoded, &rules); err != nil {
		var wrapped struct {
			Rules []policy.Rule `json:"rules"`
		}
		if wrappedErr := json.Unmarshal(encoded, &wrapped); wrappedErr != nil {
			return nil, fmt.Errorf("decode rules: %w", err)
		}
		rules = wrapped.Rules
	}
	if len(rules) == 0 {
		return nil, errors.New("rules file must contain at least one rule")
	}
	for _, rule := range rules {
		if rule.ID == "" || rule.Reason == "" {
			return nil, errors.New("every rule requires id and reason")
		}
		switch rule.Effect {
		case policy.EffectAllow, policy.EffectDeny, policy.EffectApproval, policy.EffectTyped, policy.EffectStop:
		default:
			return nil, fmt.Errorf("rule %s has unsupported effect %q", rule.ID, rule.Effect)
		}
	}
	return rules, nil
}

func (a *App) listProfiles(ctx context.Context, args []string) error {
	flags := a.flags("profile list")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("profile list does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	profiles, err := control.Profiles(ctx)
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	if *jsonOutput {
		return writeJSON(a.Out, profiles)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	for _, profile := range profiles {
		fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s/%s\n", profile.ID, profile.Name, profile.Agent, profile.Scope.Provider, profile.Scope.AccountRef)
	}
	return nil
}

func (a *App) runSession(ctx context.Context, args []string) error {
	flags := a.flags("run")
	profileReference := flags.String("profile", "", "profile name or ID")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	agentArgs := flags.Args()
	if *profileReference == "" {
		if len(agentArgs) == 0 {
			return exitError{code: 2, err: errors.New("run requires --profile or a profile name")}
		}
		*profileReference = agentArgs[0]
		agentArgs = agentArgs[1:]
	}
	store, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	if err := (enforcement.Engine{Store: store, Control: control, Now: a.Now}).Replay(ctx); err != nil {
		return fmt.Errorf("sync pending receipts before session start: %w", err)
	}
	profiles, err := control.Profiles(ctx)
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	profile, err := selectProfile(profiles, *profileReference)
	if err != nil {
		return err
	}
	if _, err := a.LookPath(string(profile.Agent)); err != nil {
		return fmt.Errorf("find %s executable: %w", profile.Agent, err)
	}
	session, err := control.StartSession(ctx, profile)
	if err != nil {
		return fmt.Errorf("start governed session: %w", err)
	}
	active := localstate.ActiveSession{Profile: profile, Session: session}
	activePath, err := store.SaveActive(active)
	if err != nil {
		return a.stopAfterStart(control, session.ID, "local state initialization failed", err)
	}
	signed, err := control.Policy(ctx, session.ID)
	if err != nil {
		return a.stopAfterStart(control, session.ID, "initial policy fetch failed", err)
	}
	publicKey, err := decodePublicKey(config.PolicyPublicKey)
	if err != nil {
		return a.stopAfterStart(control, session.ID, "enrollment key is invalid", err)
	}
	if signed.KeyID != config.PolicyKeyID {
		return a.stopAfterStart(control, session.ID, "policy key mismatch", errors.New("policy signing key does not match enrollment"))
	}
	cache := policy.Cache{Path: store.PolicyPath(session.ID), PublicKey: publicKey, Now: a.Now}
	if err := cache.Store(signed); err != nil {
		return a.stopAfterStart(control, session.ID, "initial policy verification failed", err)
	}
	executable, err := a.Executable()
	if err != nil {
		return a.stopAfterStart(control, session.ID, "runtime executable resolution failed", err)
	}
	commandName, commandArgs, err := a.nativeCommand(store, executable, session.ID, profile, agentArgs)
	if err != nil {
		return a.stopAfterStart(control, session.ID, "native adapter initialization failed", err)
	}
	environment := append(os.Environ(), "MISCONFIG_ACTIVE_SESSION="+activePath, "MISCONFIG_HOME="+store.Root)
	if profile.CredentialMode == domain.CredentialBrokered {
		providers, providerErr := control.CredentialProviders(ctx)
		if providerErr != nil {
			return a.stopAfterStart(control, session.ID, "credential provider discovery failed", providerErr)
		}
		provider, providerErr := selectCredentialProvider(providers, profile)
		if providerErr != nil {
			return a.stopAfterStart(control, session.ID, "credential provider binding unavailable", providerErr)
		}
		registry, registryErr := credentialruntime.NewRegistry(a.CredentialAdapters...)
		if registryErr != nil {
			return a.stopAfterStart(control, session.ID, "credential runtime registry failed", registryErr)
		}
		environment, registryErr = registry.Configure(provider.CredentialKind, credentialruntime.ConfigureRequest{
			Store: store, Executable: executable, ActivePath: activePath, Profile: profile,
			Session: session, Provider: provider, BaseEnv: environment,
		})
		if registryErr != nil {
			return a.stopAfterStart(control, session.ID, "credential runtime initialization failed", registryErr)
		}
	}
	fmt.Fprintf(a.Out, "Session %s started with %s.\n", session.ID, profile.Agent)
	runCtx, cancelRun := context.WithCancel(ctx)
	refreshDone := make(chan struct{})
	engine := enforcement.Engine{Store: store, Control: control, Now: a.Now}
	go a.refreshLoop(runCtx, cancelRun, refreshDone, engine, activePath)
	runErr := a.RunCommand(runCtx, commandName, commandArgs, profile.Workspace, environment, a.In, a.Out, a.Err)
	cancelRun()
	<-refreshDone
	remoteStopped := false
	if latest, loadErr := localstate.LoadActive(activePath); loadErr == nil && latest.Session.State != domain.SessionRunning {
		remoteStopped = true
		runErr = nil
	}
	reason := "agent exited normally"
	if runErr != nil {
		reason = "agent process exited with an error"
	} else if remoteStopped {
		reason = "remote stop observed"
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var stopErr error
	if !remoteStopped {
		stopErr = control.Stop(stopCtx, session.ID, reason)
	}
	_ = engine.Replay(stopCtx)
	if runErr != nil {
		if stopErr != nil {
			return fmt.Errorf("agent failed: %v; stop session: %w", runErr, stopErr)
		}
		var coded interface{ ExitCode() int }
		if errors.As(runErr, &coded) {
			return exitError{code: coded.ExitCode(), err: runErr}
		}
		return runErr
	}
	if stopErr != nil {
		return fmt.Errorf("stop governed session: %w", stopErr)
	}
	if remoteStopped {
		fmt.Fprintf(a.Out, "Session %s was stopped remotely.\n", session.ID)
	} else {
		fmt.Fprintf(a.Out, "Session %s stopped.\n", session.ID)
	}
	return nil
}

func selectCredentialProvider(providers []controlclient.CredentialProvider, profile domain.SessionProfile) (controlclient.CredentialProvider, error) {
	if profile.CredentialBinding == nil {
		return controlclient.CredentialProvider{}, errors.New("profile has no credential binding")
	}
	for _, provider := range providers {
		if provider.Release == profile.CredentialBinding.ProviderRelease && provider.Provider == profile.Scope.Provider {
			return provider, nil
		}
	}
	return controlclient.CredentialProvider{}, fmt.Errorf("provider release %s is not published for %s", profile.CredentialBinding.ProviderRelease, profile.Scope.Provider)
}

func (a *App) refreshLoop(ctx context.Context, stop context.CancelFunc, done chan<- struct{}, engine enforcement.Engine, activePath string) {
	defer close(done)
	ticker := time.NewTicker(a.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
			err := engine.Refresh(refreshCtx, activePath)
			cancel()
			if err != nil {
				fmt.Fprintf(a.Err, "misconfig policy refresh warning: %v\n", err)
				continue
			}
			active, err := localstate.LoadActive(activePath)
			if err == nil && active.Session.State != domain.SessionRunning {
				fmt.Fprintln(a.Err, "Misconfig stopped this governed session remotely.")
				stop()
				return
			}
		}
	}
}

func (a *App) stopAfterStart(control Control, sessionID, reason string, original error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := control.Stop(ctx, sessionID, reason); err != nil {
		return fmt.Errorf("%v; stop started session: %w", original, err)
	}
	return original
}

func selectProfile(profiles []domain.SessionProfile, reference string) (domain.SessionProfile, error) {
	var found []domain.SessionProfile
	for _, profile := range profiles {
		if profile.ID == reference || profile.Name == reference {
			found = append(found, profile)
		}
	}
	if len(found) == 0 {
		return domain.SessionProfile{}, fmt.Errorf("profile %q was not found", reference)
	}
	if len(found) > 1 {
		return domain.SessionProfile{}, fmt.Errorf("profile name %q is ambiguous; use its ID", reference)
	}
	return found[0], nil
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("policy public key is malformed")
	}
	return ed25519.PublicKey(decoded), nil
}

func (a *App) nativeCommand(store localstate.Store, executable, sessionID string, profile domain.SessionProfile, extra []string) (string, []string, error) {
	hookCommand := shellQuote(executable) + " hook"
	switch profile.Agent {
	case domain.AgentCodex:
		pre := hookCommand + " pre --agent codex"
		post := hookCommand + " post --agent codex"
		args := []string{
			"--dangerously-bypass-hook-trust",
			"-C", profile.Workspace,
		}
		// Codex accepts -c after the subcommand and positional prompt. Keep the
		// authoritative hook overrides last: a later user -c otherwise causes the
		// client to discard hooks parsed before the subcommand.
		args = append(args, extra...)
		args = append(args,
			"-c", codexHookOverride("PreToolUse", pre, "Misconfig is checking policy"),
			"-c", codexHookOverride("PostToolUse", post, "Misconfig is recording proof"),
		)
		return "codex", args, nil
	case domain.AgentClaude:
		settings := map[string]any{"hooks": map[string]any{
			"PreToolUse":         []any{nativeMatcher(hookCommand+" pre --agent claude", "Misconfig is checking policy")},
			"PostToolUse":        []any{nativeMatcher(hookCommand+" post --agent claude", "Misconfig is recording proof")},
			"PostToolUseFailure": []any{nativeMatcher(hookCommand+" post --agent claude", "Misconfig is recording failure")},
		}}
		path, err := store.SaveRuntimeConfig(sessionID, "claude-settings.json", settings)
		if err != nil {
			return "", nil, err
		}
		return "claude", append([]string{"--settings", path}, extra...), nil
	default:
		return "", nil, fmt.Errorf("unsupported agent %q", profile.Agent)
	}
}

func nativeMatcher(command, status string) map[string]any {
	return map[string]any{"matcher": ".*", "hooks": []any{map[string]any{
		"type": "command", "command": command, "timeout": 10, "statusMessage": status,
	}}}
}

func codexHookOverride(event, command, status string) string {
	return fmt.Sprintf("hooks.%s=[{matcher=\".*\",hooks=[{type=\"command\",command=%s,timeout=10,statusMessage=%s}]}]", event, strconv.Quote(command), strconv.Quote(status))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func runCommand(ctx context.Context, name string, args []string, directory string, environment []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func (a *App) status(ctx context.Context, args []string) error {
	flags := a.flags("status")
	jsonOutput := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("status does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	_, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	sessions, err := control.Sessions(ctx)
	if err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}
	local := sessions[:0]
	for _, session := range sessions {
		if session.DeviceID == config.DeviceID {
			local = append(local, session)
		}
	}
	if *jsonOutput {
		return writeJSON(a.Out, map[string]any{"device_id": config.DeviceID, "tenant_id": config.TenantID, "sessions": local})
	}
	fmt.Fprintf(a.Out, "Device %s is enrolled in tenant %s.\n", config.DeviceID, config.TenantID)
	if len(local) == 0 {
		fmt.Fprintln(a.Out, "No sessions from this device.")
	}
	for _, session := range local {
		fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s\n", session.ID, session.ProfileID, session.State, session.StartedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func (a *App) sync(ctx context.Context, args []string) error {
	flags := a.flags("sync")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("sync does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	store, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	spoolStore := spool.Store{Root: store.ReceiptRoot()}
	before, err := spoolStore.Pending()
	if err != nil {
		return fmt.Errorf("inspect pending receipts: %w", err)
	}
	if err := (enforcement.Engine{Store: store, Control: control, Now: a.Now}).Replay(ctx); err != nil {
		return fmt.Errorf("sync pending receipts: %w", err)
	}
	fmt.Fprintf(a.Out, "%d pending receipt(s) synchronized.\n", len(before))
	return nil
}

func (a *App) uninstall(ctx context.Context, args []string) error {
	flags := a.flags("uninstall")
	yes := flags.Bool("yes", false, "confirm removal")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("uninstall does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	if !*yes {
		return exitError{code: 2, err: errors.New("uninstall requires --yes")}
	}
	store, err := a.store()
	if err != nil {
		return err
	}
	config, err := store.LoadConfig()
	if errors.Is(err, os.ErrNotExist) {
		if err := store.Remove(); err != nil {
			return fmt.Errorf("remove unenrolled local runtime state: %w", err)
		}
		fmt.Fprintln(a.Out, "No enrollment found. Misconfig local runtime state removed.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("load enrollment before uninstall: %w", err)
	}
	token, err := store.DeviceToken(config.DeviceID)
	if err != nil {
		return fmt.Errorf("load device credential before uninstall: %w", err)
	}
	control := a.NewControl(config.ControlURL, config.TenantID, token)
	sessions, err := control.Sessions(ctx)
	if err != nil {
		return fmt.Errorf("list sessions before uninstall: %w", err)
	}
	for _, session := range sessions {
		if session.DeviceID != config.DeviceID || (session.State != domain.SessionRunning && session.State != domain.SessionStarting && session.State != domain.SessionStopping) {
			continue
		}
		if err := control.Stop(ctx, session.ID, "device runtime uninstalled"); err != nil {
			return fmt.Errorf("stop session %s before uninstall: %w", session.ID, err)
		}
	}
	if err := store.DeleteDeviceToken(config.DeviceID); err != nil {
		return err
	}
	if err := store.Remove(); err != nil {
		return fmt.Errorf("remove local runtime state: %w", err)
	}
	fmt.Fprintln(a.Out, "Misconfig local runtime state removed.")
	return nil
}

func (a *App) hook(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "pre" && args[0] != "post") {
		return exitError{code: 2, err: errors.New("hook requires pre or post")}
	}
	event := args[0]
	flags := a.flags("hook " + event)
	agent := flags.String("agent", "", "native agent")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("hook does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	if *agent != string(domain.AgentCodex) && *agent != string(domain.AgentClaude) {
		return exitError{code: 2, err: errors.New("hook --agent must be codex or claude")}
	}
	activePath := strings.TrimSpace(a.Getenv("MISCONFIG_ACTIVE_SESSION"))
	if activePath == "" {
		return a.nativeDeny(*agent, "Misconfig active session is missing")
	}
	encoded, err := io.ReadAll(io.LimitReader(a.In, 2<<20))
	if err != nil {
		return a.nativeDeny(*agent, "Misconfig could not read the tool request")
	}
	input, err := hook.Decode(encoded)
	if err != nil {
		return a.nativeDeny(*agent, "Misconfig rejected malformed hook input")
	}
	store, err := a.store()
	if err != nil {
		return a.nativeDeny(*agent, "Misconfig enrollment is unavailable")
	}
	config, err := store.LoadConfig()
	if err != nil {
		return a.nativeDeny(*agent, "Misconfig enrollment is unavailable")
	}
	if config.TenantID == "" {
		return a.nativeDeny(*agent, "Misconfig tenant binding is unavailable")
	}
	engine := enforcement.Engine{Store: store, Now: a.Now}
	if event == "post" {
		if err := engine.Post(ctx, activePath, input); err != nil {
			fmt.Fprintf(a.Err, "misconfig post-hook receipt warning: %v\n", err)
		}
		return nil
	}
	result, err := engine.Pre(ctx, activePath, input)
	if err != nil {
		return a.nativeDeny(*agent, "Misconfig could not establish a valid policy decision")
	}
	if err := a.nativeDecision(*agent, result.Decision); err != nil {
		return exitError{code: 2, err: fmt.Errorf("emit native pre-hook decision: %w", err)}
	}
	return nil
}

func (a *App) nativeDeny(agent, reason string) error {
	if err := a.nativeDecision(agent, policy.Decision{Effect: policy.EffectDeny, Reason: reason}); err != nil {
		return exitError{code: 2, err: fmt.Errorf("emit fail-closed hook decision: %w", err)}
	}
	return nil
}

func (a *App) nativeDecision(agent string, decision policy.Decision) error {
	if agent == string(domain.AgentCodex) && decision.Effect == policy.EffectAllow {
		return nil
	}
	permission := "deny"
	if agent == string(domain.AgentClaude) {
		switch decision.Effect {
		case policy.EffectAllow:
			permission = "allow"
		case policy.EffectApproval:
			permission = "ask"
		}
	}
	reason := strings.TrimSpace(decision.Reason)
	if reason == "" {
		reason = "Misconfig policy blocked this action"
	}
	encoded, err := hook.DecisionJSON("PreToolUse", permission, reason)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.Out, string(encoded))
	return err
}

func (a *App) flags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(a.Err)
	return flags
}

func (a *App) usage() {
	fmt.Fprintln(a.Err, "usage: misconfig <version|doctor|setup|profile|credential|run|status|sync|uninstall>")
	fmt.Fprintln(a.Err, "       misconfig profile <create|list|migrate>")
	fmt.Fprintln(a.Err, "       misconfig credential <providers|connection>")
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
