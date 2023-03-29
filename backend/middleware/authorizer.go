package middleware

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"

	"test_iam/generated/swagger/models"
	"test_iam/pointers"
)

type Authorizer struct {
	keycloakClient *gocloak.GoCloak // todo: use interface
	clientID       string
	idOfClient     string
	clientSecret   string
	realm          string
	token          string
	evaluator      evaluator
}

type evaluator interface {
	evaluate(accessToken, realm, clientID, clientSecret, resourceName, scope string) (bool, error)
}

type keycloakEvaluator struct {
	httpClient *http.Client
	tokenUrl   string
}

func (e *keycloakEvaluator) evaluate(accessToken, realm, clientID, clientSecret, resourceName, scope string) (bool, error) {
	data := []byte(fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&subject_token=%s&permission=%s#%s&response_mode=decision&audience=%s", accessToken, resourceName, scope, clientID))
	request, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBuffer(data))
	if err != nil {
		return false, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, clientSecret)

	resp, err := e.httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func (a *Authorizer) Authorize(request *http.Request, auth interface{}) error {
	token, ok := auth.(*models.Principal)
	if !ok {
		return errors.New(http.StatusForbidden, "invalid token")
	}
	ctx := context.Background()
	url := request.URL.String()

	resourceName, scope, err := a.getResourceScopeByUrl(ctx, url)
	if err != nil {
		return errors.New(http.StatusForbidden, "resource not found")
	}
	ok, err = a.evaluator.evaluate(string(*token), a.realm, a.clientID, a.clientSecret, resourceName, scope)
	if err != nil {
		return errors.New(http.StatusForbidden, "error evaluating permissions")
	}
	if !ok {
		return errors.New(http.StatusForbidden, "not authorized")
	}
	return nil
}

func (a *Authorizer) getResourceScopeByUrl(ctx context.Context, url string) (string, string, error) {
	jwt, err := a.keycloakClient.LoginClient(ctx, a.clientID, a.clientSecret, a.realm)
	if err != nil {
		return "", "", err
	}
	resources, err := a.keycloakClient.GetResourcesClient(ctx, jwt.AccessToken, a.realm, gocloak.GetResourceParams{})
	if err != nil {
		return "", "", err
	}
	for _, resource := range resources {
		if resource.Name == nil {
			return "", "", fmt.Errorf("resource name is nil")
		}
		if resource.URIs == nil {
			return "", "", fmt.Errorf("resource uris is nil")
		}
		for _, uri := range *resource.URIs {
			if uri == url {
				if resource.Scopes == nil {
					return "", "", fmt.Errorf("resource scopes is nil")
				}
				for _, scope := range *resource.Scopes {
					if scope.Name == nil {
						return "", "", fmt.Errorf("scope name is nil")
					}
					return *resource.Name, *scope.Name, nil
				}
			}
		}
	}
	return "", "", fmt.Errorf("resource not found %d", len(resources))
}

func NewKeycloakAuth(keycloakClient *gocloak.GoCloak, adminUser, adminPassword, clientId, realm string) (runtime.Authorizer, error) { // todo: maybe its better to use separate service to get client credentials
	ctx := context.Background()
	token, err := keycloakClient.LoginAdmin(ctx, adminUser, adminPassword, "master") // todo: remove hardcoded master
	if err != nil {
		return nil, err
	}
	clients, err := keycloakClient.GetClients(ctx, token.AccessToken, realm, gocloak.GetClientsParams{
		ClientID: pointers.ToPtr(clientId),
	})
	if err != nil {
		return nil, err
	}
	if len(clients) != 1 {
		return nil, fmt.Errorf("expected 1 client, got %d", len(clients))
	}
	client := clients[0]
	if client.Secret == nil {
		return nil, fmt.Errorf("client secret is nil")
	}
	if client.ID == nil {
		return nil, fmt.Errorf("client id is nil")
	}
	return &Authorizer{
		keycloakClient: keycloakClient,
		idOfClient:     *client.ID,
		clientSecret:   *client.Secret,
		realm:          realm,
		token:          token.AccessToken,
		clientID:       clientID,
		evaluator:      &keycloakEvaluator{httpClient: http.DefaultClient, tokenUrl: fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", "http://localhost:8080", realm)},
	}, nil
}
