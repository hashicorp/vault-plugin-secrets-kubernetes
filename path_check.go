package kubesecrets

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	checkPath            = "check"
	checkHelpSynopsis    = `Checks the Kubernetes configuration is valid.`
	checkHelpDescription = `Checks the Kubernetes configuration is valid, checking if required environment variables are set.`
)

var envVarsToCheck = []string{"KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT_HTTPS"}

func (b *backend) pathCheck() *framework.Path {
	return &framework.Path{
		Pattern: checkPath + "/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCheckRead,
			},
		},
		HelpSynopsis:    checkHelpSynopsis,
		HelpDescription: checkHelpDescription,
	}
}

func (b *backend) pathCheckRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	var missing []string
	for _, key := range envVarsToCheck {
		val := os.Getenv(key)
		if val == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) == 0 {
		return &logical.Response{
			Data: map[string]interface{}{
				logical.HTTPStatusCode: 204,
			},
		}, nil
	}

	missingText := strings.Join(missing, ", ")
	return logical.ErrorResponse(fmt.Sprintf("Missing environment variables: %s", missingText)), nil
}
