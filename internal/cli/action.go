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
	store, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	session, err := a.loadActionSession(ctx, store, config, control)
	if err != nil {
		return err
	}
	active := session.active
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
	if err := a.checkTypedAction(session, strings.TrimSpace(*operation), strings.TrimSpace(*resource), selectedEnvironment, parameters); err != nil {
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
	if !session.owns(action) {
		return errors.New("proposed action does not belong to the active session")
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
	store, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	session, err := a.loadActionSession(ctx, store, config, control)
	if err != nil {
		return err
	}
	if selected := strings.TrimSpace(*sessionID); selected != "" && selected != session.active.Session.ID {
		return errors.New("action list cannot select another session; use the console to inspect other sessions")
	}
	actions, err := control.TypedActions(ctx, session.active.Session.ID)
	if err != nil {
		return fmt.Errorf("list typed actions: %w", err)
	}
	for _, action := range actions {
		if !session.owns(action) {
			return errors.New("action list contains an action outside the active session")
		}
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
	store, config, control, err := a.authenticated()
	if err != nil {
		return err
	}
	session, err := a.loadActionSession(ctx, store, config, control)
	if err != nil {
		return err
	}
	actions, err := control.TypedActions(ctx, session.active.Session.ID)
	if err != nil {
		return fmt.Errorf("verify action belongs to active session: %w", err)
	}
	var selected *controlclient.TypedAction
	for i := range actions {
		if !session.owns(actions[i]) {
			return errors.New("action list contains an action outside the active session")
		}
		if actions[i].ID == strings.TrimSpace(*actionID) {
			selected = &actions[i]
		}
	}
	if selected == nil {
		return errors.New("action was not found in the active session")
	}
	if selected.Provider != session.active.Profile.Scope.Provider || selected.AccountRef != session.active.Profile.Scope.AccountRef || selected.PolicyRelease != session.policy.Release {
		return errors.New("action does not match the active task authority")
	}
	providerRelease := ""
	if binding := session.active.Profile.ProviderBinding; binding != nil {
		providerRelease = binding.ProviderRelease
	} else if binding := session.active.Profile.CredentialBinding; binding != nil {
		providerRelease = binding.ProviderRelease
	}
	if providerRelease == "" || selected.ProviderRelease != providerRelease {
		return errors.New("action provider release does not match the active task")
	}
	if err := a.checkTypedAction(session, selected.Operation, selected.Resource, selected.Environment, selected.Parameters); err != nil {
		return err
	}
	action, err := control.ExecuteTypedAction(ctx, strings.TrimSpace(*actionID))
	if err != nil {
		return fmt.Errorf("execute typed action: %w", err)
	}
	if !session.owns(action) || action.ID != selected.ID {
		return errors.New("execution response does not match the active session action; inspect the console before retrying")
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
