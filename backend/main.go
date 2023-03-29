package main

import (
	"context"
	"log"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-openapi/loads"

	"test_iam/generated/swagger/restapi"
	"test_iam/generated/swagger/restapi/operations"

	"test_iam/config"
	"test_iam/handlers"
	"test_iam/middleware"
	"test_iam/realm"
)

func main() {
	// config
	ctx := context.Background()
	conf, err := config.GetAppConfig()
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	// swagger
	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		log.Fatalf("Error loading swagger spec: %s", err)
	}
	api := operations.NewTestIamAPI(swaggerSpec)
	api.UseSwaggerUI()

	// keycloak
	client := gocloak.NewClient(conf.Keycloak.Url)
	keyCloakService := realm.NewKeycloakSetup(ctx, client, conf.Keycloak)
	id, secret, err := keyCloakService.SetupRealmWithClient()
	if err != nil {
		log.Fatalf("Error getting realm client credentials: %s", err)
	}
	// TODO: move this to setup
	access, err := keyCloakService.GetMasterRealmToken()
	if err != nil {
		log.Fatalf("Error getting master realm token: %s", err)
	}
	userID, err := keyCloakService.CreateUserIfNeeded(access.AccessToken, conf.Keycloak.AdminUser, conf.Keycloak.AdminPassword)
	if err != nil {
		log.Fatalf("Error creating user: %s", err)
	}
	err = keyCloakService.AddAdminRightsToUser(userID)
	if err != nil {
		log.Fatalf("Error adding admin rights to user: %s", err)
	}

	// handlers

	api.SystemGetHealthHandler = handlers.Health()
	api.UserGetUserRolesHandler = handlers.UserRoles()

	authZ, err := middleware.NewKeycloakAuth(client, conf.Keycloak.AdminUser, conf.Keycloak.AdminPassword, conf.Keycloak.ClientName, conf.Keycloak.Realm)
	if err != nil {
		log.Fatalf("Error creating authZ: %s", err)
	}
	api.APIAuthorizer = authZ

	middleware.SetupOauth(api, id, secret, conf.Keycloak.Realm)
	api.Init()
	server := restapi.NewServer(api)

	server.EnabledListeners = []string{"http"}
	server.Host = conf.Server.Host
	server.Port = conf.Server.Port

	server.SetHandler(
		api.Serve(nil),
	)
	// Swagger servers handles signals and gracefully shuts down by itself
	if err = server.Serve(); err != nil {
		log.Fatalf("Error serving: %s", err)
	}

	if errShutdown := server.Shutdown(); errShutdown != nil {
		log.Fatalf("Error shutting down: %s", errShutdown)
	}
}
