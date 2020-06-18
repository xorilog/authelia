package oidc

import (
	"log"
	"net/http"

	"github.com/authelia/authelia/internal/middlewares"
	"github.com/ory/fosite"
)

func tokenEndpoint(oauth2 fosite.OAuth2Provider) middlewares.AutheliaHandlerFunc {
	return func(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
		// This context will be passed to all methods.
		session := newSession("")

		// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
		accessRequest, err := oauth2.NewAccessRequest(ctx, req, session)

		// Catch any errors, e.g.:
		// * unknown client
		// * invalid redirect
		// * ...
		if err != nil {
			log.Printf("Error occurred in NewAccessRequest: %+v", err)
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
		// and aggregate the result in response.
		response, err := oauth2.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			log.Printf("Error occurred in NewAccessResponse: %+v", err)
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		oauth2.WriteAccessResponse(rw, accessRequest, response)
	}
}
