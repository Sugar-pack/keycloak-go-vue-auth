package realm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"

	"test_iam/config"
	"test_iam/pointers"
)

const (
	masterRealm        = "master"
	realmManagerClient = "realm-management"
	realmAdminRole     = "realm-admin"
)

type KeycloakClient interface {
	LoginAdmin(ctx context.Context, username, password, realm string) (*gocloak.JWT, error)
	GetRealm(ctx context.Context, accessToken, realm string) (*gocloak.RealmRepresentation, error)
	CreateRealm(ctx context.Context, accessToken string, realm gocloak.RealmRepresentation) (string, error)
	GetClient(ctx context.Context, accessToken, realm, clientID string) (*gocloak.Client, error)
	CreateClient(ctx context.Context, accessToken, realm string, client gocloak.Client) (string, error)
	GetClientRoles(ctx context.Context, accessToken, realm, clientID string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetClients(ctx context.Context, accessToken, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetUsers(ctx context.Context, accessToken, realm string, params gocloak.GetUsersParams) ([]*gocloak.User, error)
	CreateUser(ctx context.Context, accessToken, realm string, user gocloak.User) (string, error)
	GetClientRole(ctx context.Context, accessToken, realm, clientID, roleName string) (*gocloak.Role, error)
	AddClientRolesToUser(ctx context.Context, accessToken, realm, userID, clientID string, roles []gocloak.Role) error
	SetPassword(ctx context.Context, accessToken, userID, realm, password string, temp bool) error
}

type KeycloakSetupService struct {
	ctx    context.Context
	client KeycloakClient
	conf   config.Keycloak
}

func NewKeycloakSetup(ctx context.Context, client *gocloak.GoCloak, conf config.Keycloak) *KeycloakSetupService {
	return &KeycloakSetupService{
		ctx:    ctx,
		client: client,
		conf:   conf,
	}
}

func (k *KeycloakSetupService) SetupRealmWithClient() (string, string, error) {
	access, err := k.GetMasterRealmToken()
	if err != nil {
		return "", "", fmt.Errorf("getting master realm token: %w", err)
	}
	err = k.setupNewRealm(access.AccessToken)
	if err != nil {
		return "", "", fmt.Errorf("getting setup new realm: %w", err)
	}
	client, err := k.setupNewRealmClient(access.AccessToken)
	if err != nil {
		return "", "", fmt.Errorf("preparing new realm client: %w", err)
	}
	if client == nil || client.ClientID == nil || client.Secret == nil {
		return "", "", fmt.Errorf("client doesn't have clientID or secret")
	}
	return *client.ClientID, *client.Secret, nil
}

func (k *KeycloakSetupService) GetMasterRealmToken() (*gocloak.JWT, error) {
	return k.client.LoginAdmin(k.ctx, k.conf.AdminUser, k.conf.AdminPassword, masterRealm)
}

func (k *KeycloakSetupService) setupNewRealm(token string) error {
	_, err := k.client.GetRealm(k.ctx, token, k.conf.Realm)
	if err != nil {
		apiErr, ok := err.(*gocloak.APIError)
		if !ok {
			return fmt.Errorf("unknown err: %w", err)
		}
		if apiErr.Code != http.StatusNotFound {
			return fmt.Errorf("getting realm: %w", err)
		}
		return k.createRealm(token)
	}
	return nil
}

func (k *KeycloakSetupService) createRealm(token string) error {
	newRealm := gocloak.RealmRepresentation{
		Realm:               &k.conf.Realm,
		RegistrationAllowed: pointers.ToPtr(true), // TODO: make it configurable
		Enabled:             pointers.ToPtr(true),
	}
	_, err := k.client.CreateRealm(k.ctx, token, newRealm)
	if err != nil {
		return fmt.Errorf("creating realm: %w", err)
	}
	return nil
}

func (k *KeycloakSetupService) setupNewRealmClient(token string) (*gocloak.Client, error) {
	keycloakClients, err := k.client.GetClients(k.ctx, token, k.conf.Realm, gocloak.GetClientsParams{
		ClientID: &k.conf.ClientName,
	})
	if err != nil {
		apiErr, ok := err.(*gocloak.APIError)
		if !ok {
			return nil, fmt.Errorf("unknown err: %w", err)
		}
		if apiErr.Code != http.StatusNotFound {
			return nil, fmt.Errorf("getting client: %w", err)
		}
	}
	if len(keycloakClients) == 0 {
		return k.createClient(token)
	}
	return keycloakClients[0], nil
}

func (k *KeycloakSetupService) createClient(token string) (*gocloak.Client, error) {
	newClient := gocloak.Client{
		ClientID:                     &k.conf.ClientName,
		Name:                         &k.conf.ClientName,
		DirectAccessGrantsEnabled:    pointers.ToPtr(true),
		ServiceAccountsEnabled:       pointers.ToPtr(true),
		AuthorizationServicesEnabled: pointers.ToPtr(true),
		RedirectURIs: pointers.ToPtr([]string{
			"http://localhost:8082/api/v1/callback", // TODO: make it configurable
		}),
		Attributes: pointers.ToPtr(
			map[string]string{
				"oauth2.device.authorization.grant.enabled": "true", // TODO: make it constant
			}),
		AuthorizationSettings: &gocloak.ResourceServerRepresentation{
			Scopes: &[]gocloak.ScopeRepresentation{
				{
					Name: pointers.ToPtr(http.MethodGet),
				},
				{
					Name: pointers.ToPtr(http.MethodPost),
				},
				{
					Name: pointers.ToPtr(http.MethodPut),
				},
				{
					Name: pointers.ToPtr(http.MethodDelete),
				},
			},
		},
	}
	id, err := k.client.CreateClient(k.ctx, token, k.conf.Realm, newClient)
	if err != nil {
		return nil, fmt.Errorf("creating realm client: %w", err)
	}

	c, err := k.client.GetClient(k.ctx, token, k.conf.Realm, id)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CreateUserIfNeeded creates a new user in the realm and return the user id
func (k *KeycloakSetupService) CreateUserIfNeeded(token, username, password string) (string, error) {
	users, err := k.client.GetUsers(k.ctx, token, k.conf.Realm, gocloak.GetUsersParams{
		Username: &username,
	})
	if err != nil {
		return "", err
	}
	if len(users) > 0 {
		err = k.client.SetPassword(k.ctx, token, *users[0].ID, k.conf.Realm, password, false)
		if err != nil {
			return "", err
		}
		return *users[0].ID, nil
	}
	user := gocloak.User{
		Username: &username,
		Enabled:  pointers.ToPtr(true),
	}
	id, err := k.client.CreateUser(k.ctx, token, k.conf.Realm, user)
	if err != nil {
		return "", err
	}
	err = k.client.SetPassword(k.ctx, token, id, k.conf.Realm, password, false)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (k *KeycloakSetupService) AddAdminRightsToUser(userId string) error {
	access, err := k.GetMasterRealmToken()
	if err != nil {
		return fmt.Errorf("getting master realm token: %w", err)
	}
	clients, err := k.client.GetClients(k.ctx, access.AccessToken, k.conf.Realm, gocloak.GetClientsParams{
		ClientID: pointers.ToPtr(realmManagerClient),
	})
	if err != nil {
		return fmt.Errorf("getting realm manager client: %w", err)
	}
	if len(clients) == 0 {
		return fmt.Errorf("realm manager client not found")
	}
	client := clients[0]
	role, err := k.client.GetClientRole(k.ctx, access.AccessToken, k.conf.Realm, *client.ID, realmAdminRole)
	if err != nil {
		return fmt.Errorf("getting realm admin role: %w", err)
	}
	err = k.client.AddClientRolesToUser(k.ctx, access.AccessToken, k.conf.Realm, *client.ID, userId, []gocloak.Role{*role})
	if err != nil {
		return fmt.Errorf("adding realm admin role to user: %w", err)
	}
	return nil
}
