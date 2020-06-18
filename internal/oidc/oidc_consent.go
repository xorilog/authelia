package oidc

import (
	"encoding/json"
	"fmt"

	"github.com/authelia/authelia/internal/authorization"
	"github.com/authelia/authelia/internal/middlewares"
)

const constAccept = "accept"
const constReject = "reject"

// ConsentPostRequestBody schema of the request body of the consent POST endpoint.
type ConsentPostRequestBody struct {
	ClientID       string `json:"client_id"`
	AcceptOrReject string `json:"accept_or_reject"`
}

// ConsentPostResponseBody schema of the response body of the consent POST endpoint.
type ConsentPostResponseBody struct {
	RedirectURI string `json:"redirect_uri"`
}

// ConsentGetResponseBody schema of the response body of the consent GET endpoint.
type ConsentGetResponseBody struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// ConsentGet handler serving the list consent requested by the app.
func ConsentGet(req *middlewares.AutheliaCtx) {
	userSession := req.GetSession()

	if userSession.OIDCWorkflowSession == nil {
		req.Logger.Debug("Cannot consent when OIDC workflow has not been initiated")
		req.ReplyForbidden()

		return
	}

	if !authorization.IsAuthLevelSufficient(
		userSession.AuthenticationLevel,
		userSession.OIDCWorkflowSession.RequiredAuthorizationLevel) {
		req.Logger.Debug("Insufficient permissions to give consent")
		req.ReplyForbidden()

		return
	}

	var body ConsentGetResponseBody
	body.Scopes = userSession.OIDCWorkflowSession.RequestedScopes
	body.ClientID = userSession.OIDCWorkflowSession.ClientID

	if err := req.SetJSONBody(body); err != nil {
		req.Error(fmt.Errorf("Unable to set JSON body: %v", err), "Operation failed")
	}
}

// ConsentPost handler granting permissions according to the requested scopes.
func ConsentPost(req *middlewares.AutheliaCtx) {
	userSession := req.GetSession()

	if userSession.OIDCWorkflowSession == nil {
		req.Logger.Debug("Cannot consent when OIDC workflow has not been initiated")
		req.ReplyForbidden()

		return
	}

	if !authorization.IsAuthLevelSufficient(
		userSession.AuthenticationLevel,
		userSession.OIDCWorkflowSession.RequiredAuthorizationLevel) {
		req.Logger.Debug("Insufficient permissions to give consent")
		req.ReplyForbidden()

		return
	}

	var body ConsentPostRequestBody
	err := json.Unmarshal(req.Request.Body(), &body)

	if err != nil {
		req.Error(fmt.Errorf("Unable to unmarshal body: %v", err), "Operation failed")
		return
	}

	if body.AcceptOrReject != constAccept && body.AcceptOrReject != constReject {
		req.Logger.Infof("User %s tried to reply to consent with an unexpected verb", userSession.Username)
		req.ReplyBadRequest()

		return
	}

	if userSession.OIDCWorkflowSession.ClientID != body.ClientID {
		req.Logger.Infof("User %s consented to scopes of another client (%s) than expected (%s). Beware this can be a sign of attack",
			userSession.Username, body.ClientID, userSession.OIDCWorkflowSession.ClientID)
		req.ReplyBadRequest()

		return
	}

	var redirectionURL string

	if body.AcceptOrReject == constAccept {
		redirectionURL = userSession.OIDCWorkflowSession.AuthURI
		userSession.OIDCWorkflowSession.GrantedScopes = userSession.OIDCWorkflowSession.RequestedScopes

		if err := req.SaveSession(userSession); err != nil {
			req.Error(fmt.Errorf("Unable to write session: %v", err), "Operation failed")
			return
		}
	} else if body.AcceptOrReject == constReject {
		redirectionURL = fmt.Sprintf("%s?error=access_denied&error_description=%s",
			userSession.OIDCWorkflowSession.TargetURI, "User has rejected the scopes")
		userSession.OIDCWorkflowSession = nil

		if err := req.SaveSession(userSession); err != nil {
			req.Error(fmt.Errorf("Unable to write session: %v", err), "Operation failed")
			return
		}
	}

	response := ConsentPostResponseBody{RedirectURI: redirectionURL}

	if err := req.SetJSONBody(response); err != nil {
		req.Error(fmt.Errorf("Unable to set JSON body in response"), "Operation failed")
	}
}
