package credentialruntime

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const AWSCredentialKind = "aws.process-credentials.v1"

type AWS struct{}

func (AWS) CredentialKind() string { return AWSCredentialKind }

func (AWS) SensitiveEnvironment() []string {
	return []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	}
}

func (AWS) Configure(request ConfigureRequest) ([]string, error) {
	if request.Profile.CredentialBinding == nil || request.Executable == "" || request.ActivePath == "" || request.Session.ID == "" {
		return nil, errors.New("aws credential runtime requires an immutable binding and active session")
	}
	if request.Provider.Provider != "aws" || request.Profile.Scope.Provider != "aws" ||
		request.Provider.CredentialKind != AWSCredentialKind ||
		request.Provider.Release != request.Profile.CredentialBinding.ProviderRelease {
		return nil, errors.New("aws credential runtime provider does not match the profile")
	}
	if strings.ContainsAny(request.Executable, "\r\n") || strings.ContainsAny(request.ActivePath, "\r\n") {
		return nil, errors.New("credential process paths contain invalid characters")
	}
	process := strings.Join([]string{
		strconv.Quote(request.Executable), "credential", "lease",
		"--active", strconv.Quote(request.ActivePath),
		"--kind", strconv.Quote(AWSCredentialKind),
	}, " ")
	configPath, err := request.Store.SaveRuntimeText(request.Session.ID, "aws-config", "[profile misconfig-session]\ncredential_process = "+process+"\n")
	if err != nil {
		return nil, fmt.Errorf("write isolated aws config: %w", err)
	}
	emptyCredentials, err := request.Store.SaveRuntimeText(request.Session.ID, "aws-credentials", "")
	if err != nil {
		return nil, fmt.Errorf("write isolated aws credential boundary: %w", err)
	}
	return SetEnvironment(request.BaseEnv, map[string]string{
		"AWS_CONFIG_FILE": configPath, "AWS_SHARED_CREDENTIALS_FILE": emptyCredentials,
		"AWS_PROFILE": "misconfig-session", "AWS_DEFAULT_PROFILE": "misconfig-session",
		"AWS_SDK_LOAD_CONFIG": "1", "AWS_EC2_METADATA_DISABLED": "true",
	}), nil
}
