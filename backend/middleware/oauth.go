package middleware

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	oidc "github.com/coreos/go-oidc" // Google OpenID client
	"golang.org/x/oauth2"            // OAuth2 client

	"test_iam/generated/swagger/models"
	"test_iam/generated/swagger/restapi/operations"
	"test_iam/generated/swagger/restapi/operations/auth"
)

func SetupOauth(api *operations.TestIamAPI, clientID, clientSecret, realm string) {

	// state carries an internal token during the oauth2 workflow
	// we just need a non empty initial value
	state := "foobar" // Don't make this a global in production.

	//issuer := fmt.Sprintf("http://localhost:8080/realms/%s", realm)
	authURL := fmt.Sprintf("http://localhost:8080/realms/%s/protocol/openid-connect/auth", realm)
	tokenURL := fmt.Sprintf("http://localhost:8080/realms/%s/protocol/openid-connect/token", realm)
	userInfoURL := fmt.Sprintf("http://localhost:8080/realms/test/protocol/openid-connect/userinfo", realm)
	callbackURL := "http://localhost:8082/api/v1/callback"

	endpoint := oauth2.Endpoint{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	api.OauthSecurityAuth = func(token string, scopes []string) (interface{}, error) {
		// This handler is called by the runtime whenever a route needs authentication
		// against the 'OAuthSecurity' scheme.
		// It is passed a token extracted from the Authentication Bearer header, and
		// the list of scopes mentioned by the spec for this route.

		// NOTE: in this simple implementation, we do not check scopes against
		// the signed claims in the JWT token.
		// So whatever the required scope (passed a parameter by the runtime),
		// this will succeed provided we get a valid token.

		// authenticated validates a JWT token at userInfoURL
		ok, err := authenticated(token, userInfoURL)
		if err != nil {
			return nil, errors.New(401, "error authenticate")
		}
		if !ok {
			return nil, errors.New(401, "invalid token")
		}

		// returns the authenticated principal (here just filled in with its token)
		prin := models.Principal(token)
		return &prin, nil
	}

	api.AuthGetCallbackHandler = auth.GetCallbackHandlerFunc(func(params auth.GetCallbackParams) middleware.Responder {
		// implements the callback operation
		token, err := callback(params.HTTPRequest, config, state)
		if err != nil {
			return middleware.ResponderFunc(
				func(w http.ResponseWriter, pr runtime.Producer) {
					io.WriteString(w, err.Error())
				})
		}
		return auth.NewGetCallbackOK().WithPayload(&auth.GetCallbackOKBody{AccessToken: token})

	})

	api.AuthGetLoginHandler = auth.GetLoginHandlerFunc(func(params auth.GetLoginParams) middleware.Responder {
		// implements the login operation
		return login(params.HTTPRequest, config, state)
	})
}

func login(r *http.Request, config *oauth2.Config, state string) middleware.Responder {
	// implements the login with a redirection
	return middleware.ResponderFunc(
		func(w http.ResponseWriter, pr runtime.Producer) {
			http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
		})
}

func callback(r *http.Request, config *oauth2.Config, state string) (string, error) {
	// we expect the redirected client to call us back
	// with 2 query params: state and code.
	// We use directly the Request params here, since we did not
	// bother to document these parameters in the spec.

	if r.URL.Query().Get("state") != state {
		log.Println("state did not match")
		return "", fmt.Errorf("state did not match")
	}

	myClient := &http.Client{}

	parentContext := context.Background()
	ctx := oidc.ClientContext(parentContext, myClient)

	authCode := r.URL.Query().Get("code")
	log.Printf("Authorization code: %v\n", authCode)

	// Exchange converts an authorization code into a token.
	// Under the hood, the oauth2 client POST a request to do so
	// at tokenURL, then redirects...
	oauth2Token, err := config.Exchange(ctx, authCode)
	if err != nil {
		log.Println("failed to exchange token", err.Error())
		return "", fmt.Errorf("failed to exchange token")
	}

	// the authorization server's returned token
	log.Println("Raw token data:", oauth2Token)
	return oauth2Token.AccessToken, nil
}

func authenticated(token string, userInfoURL string) (bool, error) {
	// validates the token by sending a request at userInfoURL
	bearToken := "Bearer " + token
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return false, fmt.Errorf("http request: %v", err)
	}

	req.Header.Add("Authorization", bearToken)

	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return false, fmt.Errorf("http request: %v", err)
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("fail to get response: %v", err)
	}
	if resp.StatusCode != 200 {
		return false, nil
	}
	return true, nil
}
