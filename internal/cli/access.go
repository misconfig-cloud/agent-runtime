package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
)

func (a *App) access(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "list" {
		return exitError{code: 2, err: errors.New("access requires list")}
	}
	_, _, control, err := a.authenticated()
	if err != nil {
		return err
	}
	access, err := control.ReusableAccess(ctx)
	if err != nil {
		return fmt.Errorf("list reusable access: %w", err)
	}
	sort.Slice(access, func(i, j int) bool { return access[i].Name < access[j].Name })
	for _, item := range access {
		if item.State == "active" {
			fmt.Fprintf(a.Out, "%s\t%s\t%s\t%s/%s\t%s\n", item.ID, item.Name, item.SimplePolicy.Preset, item.Provider, item.AccountRef, item.Environment)
		}
	}
	return nil
}

func selectReusableAccess(access []controlclient.ReusableAccess, reference string) (controlclient.ReusableAccess, error) {
	reference = strings.TrimSpace(reference)
	var selected *controlclient.ReusableAccess
	for i := range access {
		if access[i].State != "active" || (access[i].ID != reference && access[i].Name != reference) {
			continue
		}
		if selected != nil {
			return controlclient.ReusableAccess{}, errors.New("reusable access name is ambiguous; use its ID")
		}
		selected = &access[i]
	}
	if selected == nil {
		return controlclient.ReusableAccess{}, errors.New("reusable access was not found or is revoked")
	}
	return *selected, nil
}
