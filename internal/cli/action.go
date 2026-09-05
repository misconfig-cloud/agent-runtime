package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

const maximumActionParametersSize = 64 << 10

func (a *App) action(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return exitError{code: 2, err: errors.New("action requires propose, list, or execute")}
	}
	switch args[0] {
	case "propose":
		return a.proposeAction(ctx, args[1:])
	case "list":
		return a.listActions(ctx, args[1:])
	case "execute":
		return a.executeAction(ctx, args[1:])
	default:
		return exitError{code: 2, err: fmt.Errorf("unknown action command %q", args[0])}
	}
}

func (a *App) proposeAction(ctx context.Context, args []string) error {
	flags := a.flags("action propose")
	capability := flags.String("capability", "", "adapter-published capability reference")
	operation := flags.String("operation", "", "typed provider operation")
	resource := flags.String("resource", "", "exact provider resource identity")
	environment := flags.String("environment", "", "session environment")
	parametersFile := flags.String("parameters-file", "", "JSON parameters file, or - for stdin")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if flags.NArg() != 0 {
		return exitError{code: 2, err: errors.New("action propose does not accept positional arguments")}
	}
	if !allPresent(*capability, *operation, *resource, *parametersFile) {
		return exitError{code: 2, err: errors.New("action propose requires --capability, --operation, --resource, and --parameters-file")}
	}
	_, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	active, err := a.activeSession(config)
	if err != nil {
		return err
	}
	selectedEnvironment := strings.TrimSpace(*environment)
	if selectedEnvironment == "" {
		if len(active.Profile.Scope.Environments) != 1 {
			return exitError{code: 2, err: errors.New("--environment is required when the session has more than one environment")}
		}
		selectedEnvironment = active.Profile.Scope.Environments[0]
	}
	parameters, err := a.readActionParameters(*parametersFile)
	if err != nil {
		return err
	}
	action, err := control.CreateTypedAction(ctx, controlclient.CreateTypedActionRequest{
		SessionID: active.Session.ID, CapabilityRef: strings.TrimSpace(*capability),
		Operation: strings.TrimSpace(*operation), Resource: strings.TrimSpace(*resource),
		Environment: selectedEnvironment, Parameters: parameters,
	})
	if err != nil {
		return fmt.Errorf("propose typed action: %w", err)
	}
	return writeJSON(a.Out, action)
}

func (a *App) listActions(ctx context.Context, args []string) error {
	flags := a.flags("action list")
	sessionID := flags.String("session", "", "session ID; defaults to MISCONFIG_ACTIVE_SESSION")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if flags.NArg() != 0 {
		return exitError{code: 2, err: errors.New("action list does not accept positional arguments")}
	}
	_, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	selectedSession := strings.TrimSpace(*sessionID)
	if selectedSession == "" {
		active, err := a.activeSession(config)
		if err != nil {
			return err
		}
		selectedSession = active.Session.ID
	}
	actions, err := control.TypedActions(ctx, selectedSession)
	if err != nil {
		return fmt.Errorf("list typed actions: %w", err)
	}
	return writeJSON(a.Out, map[string]any{"actions": actions})
}

func (a *App) executeAction(ctx context.Context, args []string) error {
	flags := a.flags("action execute")
	actionID := flags.String("id", "", "approved typed action ID")
	if err := flags.Parse(args); err != nil {
		return exitError{code: 2, err: err}
	}
	if *actionID == "" && flags.NArg() == 1 {
		*actionID = flags.Arg(0)
	} else if flags.NArg() != 0 || strings.TrimSpace(*actionID) == "" {
		return exitError{code: 2, err: errors.New("action execute requires --id or one action ID")}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	action, err := control.ExecuteTypedAction(ctx, strings.TrimSpace(*actionID))
	if err != nil {
		return fmt.Errorf("execute typed action: %w", err)
	}
	return writeJSON(a.Out, action)
}

func (a *App) activeSession(config localstate.Config) (localstate.ActiveSession, error) {
	path := strings.TrimSpace(a.Getenv("MISCONFIG_ACTIVE_SESSION"))
	if path == "" {
		return localstate.ActiveSession{}, errors.New("MISCONFIG_ACTIVE_SESSION is missing; run this command inside `misconfig run`")
	}
	active, err := localstate.LoadActive(filepath.Clean(path))
	if err != nil {
		return localstate.ActiveSession{}, fmt.Errorf("load active session: %w", err)
	}
	if active.Session.TenantID != config.TenantID || active.Session.DeviceID != config.DeviceID ||
		active.Session.ProfileID != active.Profile.ID || active.Session.State != domain.SessionRunning {
		return localstate.ActiveSession{}, errors.New("active session identity is invalid or no longer running")
	}
	return active, nil
}

func (a *App) readActionParameters(path string) (json.RawMessage, error) {
	var reader io.Reader
	var file *os.File
	if path == "-" {
		reader = a.In
	} else {
		opened, err := os.Open(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("open action parameters: %w", err)
		}
		file, reader = opened, opened
		defer file.Close()
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, maximumActionParametersSize+1))
	if err != nil {
		return nil, fmt.Errorf("read action parameters: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumActionParametersSize || !json.Valid(encoded) {
		return nil, errors.New("action parameters must be valid JSON no larger than 64 KiB")
	}
	var object map[string]any
	if json.Unmarshal(encoded, &object) != nil || object == nil {
		return nil, errors.New("action parameters must be a JSON object")
	}
	return json.RawMessage(encoded), nil
}

func allPresent(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}
