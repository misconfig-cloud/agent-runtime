package credentialruntime

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/misconfig-cloud/agent-runtime/internal/controlclient"
	"github.com/misconfig-cloud/agent-runtime/internal/domain"
	"github.com/misconfig-cloud/agent-runtime/internal/localstate"
)

type ConfigureRequest struct {
	Store      localstate.Store
	Executable string
	ActivePath string
	Profile    domain.SessionProfile
	Session    domain.AgentSession
	Provider   controlclient.CredentialProvider
	BaseEnv    []string
}

type Adapter interface {
	CredentialKind() string
	SensitiveEnvironment() []string
	Configure(ConfigureRequest) ([]string, error)
}

type Registry struct {
	adapters map[string]Adapter
}

// ReplaceAdapter returns a new adapter set where replacement is the sole
// implementation for its credential kind. Callers must use this only after an
// external adapter release has passed admission and artifact verification.
// NewRegistry continues to reject every other duplicate registration.
func ReplaceAdapter(adapters []Adapter, replacement Adapter) ([]Adapter, error) {
	if replacement == nil || strings.TrimSpace(replacement.CredentialKind()) == "" {
		return nil, errors.New("replacement credential runtime adapter and kind are required")
	}
	kind := replacement.CredentialKind()
	result := make([]Adapter, 0, len(adapters)+1)
	for _, adapter := range adapters {
		if adapter == nil || strings.TrimSpace(adapter.CredentialKind()) == "" {
			return nil, errors.New("credential runtime adapter and kind are required")
		}
		if adapter.CredentialKind() == kind {
			continue
		}
		result = append(result, adapter)
	}
	return append(result, replacement), nil
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{adapters: make(map[string]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil || strings.TrimSpace(adapter.CredentialKind()) == "" {
			return nil, errors.New("credential runtime adapter and kind are required")
		}
		if _, exists := registry.adapters[adapter.CredentialKind()]; exists {
			return nil, fmt.Errorf("credential runtime kind %q is duplicated", adapter.CredentialKind())
		}
		registry.adapters[adapter.CredentialKind()] = adapter
	}
	return registry, nil
}

func (r *Registry) Configure(kind string, request ConfigureRequest) ([]string, error) {
	adapter, ok := r.adapters[kind]
	if !ok {
		return nil, fmt.Errorf("credential runtime adapter %q is not installed", kind)
	}
	base := withoutEnvironment(request.BaseEnv, r.sensitiveEnvironment())
	request.BaseEnv = base
	return adapter.Configure(request)
}

func (r *Registry) sensitiveEnvironment() []string {
	unique := map[string]struct{}{}
	for _, adapter := range r.adapters {
		for _, name := range adapter.SensitiveEnvironment() {
			unique[name] = struct{}{}
		}
	}
	items := make([]string, 0, len(unique))
	for name := range unique {
		items = append(items, name)
	}
	sort.Strings(items)
	return items
}

func withoutEnvironment(environment, names []string) []string {
	denied := make(map[string]struct{}, len(names))
	for _, name := range names {
		denied[name] = struct{}{}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if _, blocked := denied[name]; !blocked {
			result = append(result, entry)
		}
	}
	return result
}

func SetEnvironment(environment []string, values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	environment = withoutEnvironment(environment, names)
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	return environment
}
