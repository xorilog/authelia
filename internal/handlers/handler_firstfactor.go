package handlers

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/authelia/authelia/internal/authentication"
	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/regulation"
	"github.com/authelia/authelia/internal/session"
)

func movingAverageIteration(ctx *middlewares.AutheliaCtx, requestTime time.Time, successful bool, movingAverageCursor *int, execDurationMovingAverage *[]time.Duration, mutex sync.Locker) float64 {
	ctx.Logger.Trace("Hit fist factor post moving average iteration mutex lock")
	mutex.Lock()

	ctx.Logger.Trace("Hit fist factor post moving average iteration cursor start")
	if successful {
		(*execDurationMovingAverage)[*movingAverageCursor] = time.Since(requestTime)
		*movingAverageCursor = (*movingAverageCursor + 1) % movingAverageWindow
	}
	ctx.Logger.Trace("Hit fist factor post moving average iteration cursor end")

	var sum int64

	ctx.Logger.Trace("Hit fist factor post moving average iteration average start")
	for _, v := range *execDurationMovingAverage {
		sum += v.Milliseconds()
	}
	ctx.Logger.Trace("Hit fist factor post moving average iteration average end")
	mutex.Unlock()

	ctx.Logger.Trace("Hit fist factor post moving average iteration mutex unlock")

	return float64(sum / movingAverageWindow)
}

func calculateActualDelay(ctx *middlewares.AutheliaCtx, requestTime time.Time, avgExecDurationMs float64, successful *bool) float64 {
	execDuration := time.Since(requestTime)
	ctx.Logger.Trace("Hit fist factor post calc actual delay rand start")
	randomDelayMs := float64(rand.Int63n(msMaximumRandomDelay)) //nolint:gosec // TODO: Consider use of crypto/rand, this should be benchmarked and measured first.
	ctx.Logger.Trace("Hit fist factor post calc actual delay rand end")
	totalDelayMs := math.Max(avgExecDurationMs, msMinimumDelay1FA) + randomDelayMs
	actualDelayMs := math.Max(totalDelayMs-float64(execDuration.Milliseconds()), 1.0)
	ctx.Logger.Tracef("attempt successful: %t, exec duration ms: %d, avg execution duration ms: %d, random delay ms: %d, total delay ms: %d, actual delay ms: %d", *successful, execDuration.Milliseconds(), int64(avgExecDurationMs), int64(randomDelayMs), int64(totalDelayMs), int64(actualDelayMs))

	return actualDelayMs
}

func delayToPreventTimingAttacks(ctx *middlewares.AutheliaCtx, requestTime time.Time, successful *bool, movingAverageCursor *int, execDurationMovingAverage *[]time.Duration, mutex sync.Locker) {
	ctx.Logger.Trace("Hit first factor post deferred delay to prevent timing attacks start")

	avgExecDurationMs := movingAverageIteration(ctx, requestTime, *successful, movingAverageCursor, execDurationMovingAverage, mutex)
	actualDelayMs := calculateActualDelay(ctx, requestTime, avgExecDurationMs, successful)

	ctx.Logger.Trace("Hit first factor post deferred delay to prevent timing attacks sleep start")
	time.Sleep(time.Duration(actualDelayMs) * time.Millisecond)

	ctx.Logger.Trace("Hit first factor post deferred delay to prevent timing attacks complete")
}

// FirstFactorPost is the handler performing the first factory.
//nolint:gocyclo // TODO: Consider refactoring time permitting.
func FirstFactorPost(msInitialDelay time.Duration, delayEnabled bool) middlewares.RequestHandler {
	var execDurationMovingAverage = make([]time.Duration, movingAverageWindow)

	var movingAverageCursor = 0

	var mutex = &sync.Mutex{}

	for i := range execDurationMovingAverage {
		execDurationMovingAverage[i] = msInitialDelay * time.Millisecond
	}

	rand.Seed(time.Now().UnixNano())

	return func(ctx *middlewares.AutheliaCtx) {
		var successful bool

		requestTime := time.Now()

		ctx.Logger.Trace("Hit first factor post handler")
		if delayEnabled {
			defer delayToPreventTimingAttacks(ctx, requestTime, &successful, &movingAverageCursor, &execDurationMovingAverage, mutex)
		}

		ctx.Logger.Trace("Hit first factor post parsing body start")

		bodyJSON := firstFactorRequestBody{}
		err := ctx.ParseBody(&bodyJSON)

		ctx.Logger.Trace("Hit first factor post parsing body complete")

		if err != nil {
			handleAuthenticationUnauthorized(ctx, err, authenticationFailedMessage)
			return
		}

		ctx.Logger.Trace("Hit first factor post regulator check start")

		bannedUntil, err := ctx.Providers.Regulator.Regulate(bodyJSON.Username)

		ctx.Logger.Trace("Hit first factor post regulator check complete")

		if err != nil {
			if err == regulation.ErrUserIsBanned {
				handleAuthenticationUnauthorized(ctx, fmt.Errorf("User %s is banned until %s", bodyJSON.Username, bannedUntil), userBannedMessage)
				return
			}

			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regulate authentication: %s", err.Error()), authenticationFailedMessage)

			return
		}

		ctx.Logger.Trace("Hit first factor post password check start")

		userPasswordOk, err := ctx.Providers.UserProvider.CheckUserPassword(bodyJSON.Username, bodyJSON.Password)

		ctx.Logger.Trace("Hit first factor post password check complete")

		if err != nil {
			ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)

			if err := ctx.Providers.Regulator.Mark(bodyJSON.Username, false); err != nil {
				ctx.Logger.Errorf("Unable to mark authentication: %s", err.Error())
			}

			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Error while checking password for user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)

			return
		}

		if !userPasswordOk {
			ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)

			if err := ctx.Providers.Regulator.Mark(bodyJSON.Username, false); err != nil {
				ctx.Logger.Errorf("Unable to mark authentication: %s", err.Error())
			}

			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Credentials are wrong for user %s", bodyJSON.Username), authenticationFailedMessage)

			return
		}

		ctx.Logger.Debugf("Mark authentication attempt made by user %s", bodyJSON.Username)
		err = ctx.Providers.Regulator.Mark(bodyJSON.Username, true)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to mark authentication: %s", err.Error()), authenticationFailedMessage)
			return
		}

		ctx.Logger.Debugf("Credentials validation of user %s is ok", bodyJSON.Username)

		// Reset all values from previous session before regenerating the cookie.
		err = ctx.SaveSession(session.NewDefaultUserSession())

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to reset the session for user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
			return
		}

		err = ctx.Providers.SessionProvider.RegenerateSession(ctx.RequestCtx)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regenerate session for user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
			return
		}

		// Check if bodyJSON.KeepMeLoggedIn can be deref'd and derive the value based on the configuration and JSON data
		keepMeLoggedIn := ctx.Providers.SessionProvider.RememberMe != 0 && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

		// Set the cookie to expire if remember me is enabled and the user has asked us to
		if keepMeLoggedIn {
			err = ctx.Providers.SessionProvider.UpdateExpiration(ctx.RequestCtx, ctx.Providers.SessionProvider.RememberMe)
			if err != nil {
				handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update expiration timer for user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
				return
			}
		}

		// Get the details of the given user from the user provider.
		userDetails, err := ctx.Providers.UserProvider.GetDetails(bodyJSON.Username)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Error while retrieving details from user %s: %s", bodyJSON.Username, err.Error()), authenticationFailedMessage)
			return
		}

		ctx.Logger.Tracef("Details for user %s => groups: %s, emails %s", bodyJSON.Username, userDetails.Groups, userDetails.Emails)

		// And set those information in the new session.
		userSession := ctx.GetSession()
		userSession.Username = userDetails.Username
		userSession.DisplayName = userDetails.DisplayName
		userSession.Groups = userDetails.Groups
		userSession.Emails = userDetails.Emails
		userSession.AuthenticationLevel = authentication.OneFactor
		userSession.LastActivity = time.Now().Unix()
		userSession.KeepMeLoggedIn = keepMeLoggedIn
		refresh, refreshInterval := getProfileRefreshSettings(ctx.Configuration.AuthenticationBackend)

		if refresh {
			userSession.RefreshTTL = ctx.Clock.Now().Add(refreshInterval)
		}

		err = ctx.SaveSession(userSession)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to save session of user %s", bodyJSON.Username), authenticationFailedMessage)
			return
		}

		successful = true

		Handle1FAResponse(ctx, bodyJSON.TargetURL, bodyJSON.RequestMethod, userSession.Username, userSession.Groups)
	}
}
