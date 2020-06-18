package middlewares

import (
	"fmt"
)

func GetForwardedOrigin(ctx *AutheliaCtx) (string, error) {
	if ctx.XForwardedProto() == nil {
		return "", errMissingXForwardedProto
	}

	if ctx.XForwardedHost() == nil {
		return "", errMissingXForwardedHost
	}

	return fmt.Sprintf("%s://%s%s", ctx.XForwardedProto(),
		ctx.XForwardedHost(), ctx.Configuration.Server.Path), nil
}

func GetForwardedOriginWithBasePath(ctx *AutheliaCtx) (string, error) {
	forwardedOrigin, err := GetForwardedOrigin(ctx)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s", forwardedOrigin, ctx.Configuration.Server.Path), nil
}
