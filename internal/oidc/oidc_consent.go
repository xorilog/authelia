package oidc

import (
	"encoding/json"
	"fmt"

	"github.com/authelia/authelia/internal/authorization"
	"github.com/authelia/authelia/internal/middlewares"
)

// ConsentPostRequestBody schema of the request body of the consent POST endpoint.
type ConsentPostRequestBody struct {
	ClientID string `json:"client_id"`
}

// ConsentGetResponseBody schema of the response body of the consent GET endpoint.
type ConsentGetResponseBody struct {
	ClientID          string  `json:"client_id"`
	ClientDescription string  `json:"client_description"`
	Scopes            []Scope `json:"scopes"`
}

// Scope represents the scope information.
type Scope struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func scopeNamesToScopes(scopeSlice []string) (scopes []Scope) {
	for _, scope := range scopeSlice {
		if val, ok := scopeDescriptions[scope]; ok {
			scopes = append(scopes, Scope{scope, val})
		}
	}

	return scopes
}

// ConsentGet handler serving the list consent requested by the app.
func ConsentGet(ctx *middlewares.AutheliaCtx) {
	userSession := ctx.GetSession()
	ctx.Logger.Debugf("Hit consent (GET) endpoint")

	if userSession.OIDCWorkflowSession == nil {
		ctx.Logger.Debug("Cannot consent when OIDC workflow has not been initiated")
		ctx.ReplyForbidden()

		return
	}

	if !authorization.IsAuthLevelSufficient(
		userSession.AuthenticationLevel,
		userSession.OIDCWorkflowSession.RequiredAuthorizationLevel) {
		ctx.Logger.Debugf("Insufficient permissions to give consent v2 %d -> %d", userSession.AuthenticationLevel, userSession.OIDCWorkflowSession.RequiredAuthorizationLevel)
		ctx.ReplyForbidden()

		return
	}

	var body ConsentGetResponseBody
	body.Scopes = scopeNamesToScopes(userSession.OIDCWorkflowSession.RequestedScopes)
	body.ClientID = userSession.OIDCWorkflowSession.ClientID

	for _, client := range ctx.Configuration.IdentityProviders.OIDC.Clients {
		if client.ID == userSession.OIDCWorkflowSession.ClientID {
			body.ClientDescription = client.Description

			break
		}
	}

	if err := ctx.SetJSONBody(body); err != nil {
		ctx.Error(fmt.Errorf("Unable to set JSON body: %v", err), "Operation failed")
	}
}

// ConsentPost handler granting permissions according to the requested scopes.
func ConsentPost(ctx *middlewares.AutheliaCtx) {
	userSession := ctx.GetSession()

	ctx.Logger.Debugf("Hit consent (POST) endpoint")

	if userSession.OIDCWorkflowSession == nil {
		ctx.Logger.Debug("Cannot consent when OIDC workflow has not been initiated")
		ctx.ReplyForbidden()

		return
	}

	if !authorization.IsAuthLevelSufficient(
		userSession.AuthenticationLevel,
		userSession.OIDCWorkflowSession.RequiredAuthorizationLevel) {
		ctx.Logger.Debugf("Insufficient permissions to give consent v1 %d -> %d", userSession.AuthenticationLevel, userSession.OIDCWorkflowSession.RequiredAuthorizationLevel)
		ctx.ReplyForbidden()

		return
	}

	var body ConsentPostRequestBody
	err := json.Unmarshal(ctx.Request.Body(), &body)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to unmarshal body: %v", err), "Operation failed")
		return
	}

	if userSession.OIDCWorkflowSession.ClientID != body.ClientID {
		ctx.Logger.Infof("User %s consented to scopes of another client (%s) than expected (%s). Beware this can be a sign of attack",
			userSession.Username, body.ClientID, userSession.OIDCWorkflowSession.ClientID)
		ctx.ReplyBadRequest()

		return
	}

	userSession.OIDCWorkflowSession.GrantedScopes = userSession.OIDCWorkflowSession.RequestedScopes
	if err := ctx.SaveSession(userSession); err != nil {
		ctx.Error(fmt.Errorf("Unable to write session: %v", err), "Operation failed")
		return
	}

	ctx.Redirect(userSession.OIDCWorkflowSession.OriginalURI, 302)
}
