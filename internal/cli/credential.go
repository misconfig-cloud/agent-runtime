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
	"time"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

func (a *App) credential(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return exitError{code: 2, err: errors.New("credential requires providers, connection, or the internal lease command")}
	}
	switch args[0] {
	case "providers":
		return a.listCredentialProviders(ctx, args[1:])
	case "connection":
		return a.credentialConnection(ctx, args[1:])
	case "lease":
		return a.credentialLease(ctx, args[1:])
	default:
		return exitError{code: 2, err: fmt.Errorf("unknown credential command %q", args[0])}
	}
}

func (a *App) listCredentialProviders(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return exitError{code: 2, err: errors.New("credential providers does not accept arguments")}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	providers, err := control.CredentialProviders(ctx)
	if err != nil {
		return fmt.Errorf("list credential providers: %w", err)
	}
	return writeJSON(a.Out, map[string]any{"providers": providers})
}

func (a *App) credentialConnection(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return exitError{code: 2, err: errors.New("credential connection requires create, list, verify, or revoke")}
	}
	switch args[0] {
	case "create":
		return a.createCredentialConnection(ctx, args[1:])
	case "list":
		return a.listCredentialConnections(ctx, args[1:])
	case "verify":
		return a.verifyCredentialConnection(ctx, args[1:])
	case "revoke":
		return a.revokeCredentialConnection(ctx, args[1:])
	default:
		return exitError{code: 2, err: fmt.Errorf("unknown credential connection command %q", args[0])}
	}
}

func (a *App) createCredentialConnection(ctx context.Context, args []string) error {
	flags := a.flags("credential connection create")
	provider := flags.String("provider", "", "provider identifier")
	release := flags.String("release", "", "immutable provider release")
	account := flags.String("account", "", "provider account, project, cluster, or target reference")
	name := flags.String("name", "", "connection name")
	inputFile := flags.String("input-file", "", "provider input JSON file, or - for stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("credential connection create does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	if strings.TrimSpace(*provider) == "" || strings.TrimSpace(*release) == "" || strings.TrimSpace(*account) == "" || strings.TrimSpace(*name) == "" || strings.TrimSpace(*inputFile) == "" {
		return exitError{code: 2, err: errors.New("provider, release, account, name, and input-file are required")}
	}
	input, err := a.readCredentialInput(*inputFile)
	if err != nil {
		return err
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	prepared, err := control.CreateCredentialConnection(ctx, controlclient.CreateCredentialConnectionRequest{
		Provider: strings.TrimSpace(*provider), ProviderRelease: strings.TrimSpace(*release),
		AccountRef: strings.TrimSpace(*account), Name: strings.TrimSpace(*name), Input: input,
	})
	if err != nil {
		return fmt.Errorf("create credential connection: %w", err)
	}
	return writeJSON(a.Out, prepared)
}

func (a *App) readCredentialInput(path string) (json.RawMessage, error) {
	var encoded []byte
	var err error
	if path == "-" {
		encoded, err = io.ReadAll(io.LimitReader(a.In, 1<<20))
	} else {
		encoded, err = os.ReadFile(filepath.Clean(path))
	}
	if err != nil {
		return nil, fmt.Errorf("read credential provider input: %w", err)
	}
	if len(encoded) == 0 || !json.Valid(encoded) {
		return nil, errors.New("credential provider input must be valid JSON")
	}
	return json.RawMessage(encoded), nil
}

func (a *App) listCredentialConnections(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return exitError{code: 2, err: errors.New("credential connection list does not accept arguments")}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	connections, err := control.CredentialConnections(ctx)
	if err != nil {
		return fmt.Errorf("list credential connections: %w", err)
	}
	return writeJSON(a.Out, map[string]any{"connections": connections})
}

func (a *App) verifyCredentialConnection(ctx context.Context, args []string) error {
	flags := a.flags("credential connection verify")
	id := flags.String("id", "", "connection ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(*id) == "" {
		if err == nil {
			err = errors.New("connection id is required and positional arguments are not accepted")
		}
		return exitError{code: 2, err: err}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	connection, err := control.VerifyCredentialConnection(ctx, strings.TrimSpace(*id))
	if err != nil {
		return fmt.Errorf("verify credential connection: %w", err)
	}
	return writeJSON(a.Out, connection)
}

func (a *App) revokeCredentialConnection(ctx context.Context, args []string) error {
	flags := a.flags("credential connection revoke")
	id := flags.String("id", "", "connection ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(*id) == "" {
		if err == nil {
			err = errors.New("connection id is required and positional arguments are not accepted")
		}
		return exitError{code: 2, err: err}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	if err := control.RevokeCredentialConnection(ctx, strings.TrimSpace(*id)); err != nil {
		return fmt.Errorf("revoke credential connection: %w", err)
	}
	fmt.Fprintf(a.Out, "Revoked credential connection %s. New leases are blocked; already-issued material expires at its provider deadline.\n", strings.TrimSpace(*id))
	return nil
}

func (a *App) credentialLease(ctx context.Context, args []string) error {
	flags := a.flags("credential lease")
	activePath := flags.String("active", "", "active session path")
	kind := flags.String("kind", "", "expected credential material kind")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		if err == nil {
			err = errors.New("credential lease does not accept positional arguments")
		}
		return exitError{code: 2, err: err}
	}
	if strings.TrimSpace(*activePath) == "" {
		*activePath = strings.TrimSpace(os.Getenv("MISCONFIG_ACTIVE_SESSION"))
	}
	if strings.TrimSpace(*activePath) == "" || strings.TrimSpace(*kind) == "" {
		return exitError{code: 2, err: errors.New("active session and expected credential kind are required")}
	}
	active, err := localstate.LoadActive(*activePath)
	if err != nil {
		return fmt.Errorf("load active session: %w", err)
	}
	if active.Session.State != domain.SessionRunning || active.Profile.CredentialMode != domain.CredentialBrokered || active.Profile.CredentialBinding == nil {
		return errors.New("credential lease requires a running brokered session")
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	providers, err := control.CredentialProviders(ctx)
	if err != nil {
		return fmt.Errorf("discover credential provider: %w", err)
	}
	provider, err := selectCredentialProvider(providers, active.Profile)
	if err != nil {
		return err
	}
	if provider.CredentialKind != *kind {
		return errors.New("credential material kind does not match the immutable provider release")
	}
	requestID, err := domain.NewID("lease")
	if err != nil {
		return err
	}
	material, err := control.CredentialLease(ctx, active.Session.ID, requestID)
	if err != nil {
		return fmt.Errorf("issue credential lease: %w", err)
	}
	now := a.Now()
	maximumTTL := time.Duration(provider.MaximumTTLSeconds) * time.Second
	if material.Kind != provider.CredentialKind || material.TargetIdentity == "" ||
		material.RevocationSemantics != provider.RevocationSemantics ||
		!material.ExpiresAt.After(now) || maximumTTL <= 0 || material.ExpiresAt.After(now.Add(maximumTTL).Add(time.Second)) ||
		len(material.Payload) == 0 || !json.Valid(material.Payload) {
		return errors.New("control plane returned invalid credential material")
	}
	if _, err := a.Out.Write(material.Payload); err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.Out)
	return err
}
