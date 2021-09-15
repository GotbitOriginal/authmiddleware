package authmiddleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gotbitoriginal/auth/proto/session"
)

const (
	AuthStatus = "authStatus"
	ID         = "id"
	Login      = "login"
	Role       = "role"
)

type AuthMiddleware struct {
	AuthChecker session.AuthCheckerClient
}

func NewAuthMiddleware(AuthChecker session.AuthCheckerClient) AuthMiddleware {
	return AuthMiddleware{
		AuthChecker: AuthChecker,
	}
}

func (am *AuthMiddleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
	
		tokenHeader := r.Header.Get("Authorization") //Grab the token from the header
		splitted := strings.Split(tokenHeader, " ")  //The token normally comes in format `Bearer {token-body}`, we check if the retrieved token matched this requirement

		if tokenHeader == "" || len(splitted) != 2 {
			ctx = context.WithValue(ctx, AuthStatus, false) // nolint:staticcheck
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		token := splitted[1]

		sess, err := am.AuthChecker.Check(context.Background(), &session.Credentials{Token: token})
		if err != nil {
			ctx = context.WithValue(ctx, AuthStatus, false) // nolint:staticcheck
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, AuthStatus, true)  // nolint:staticcheck
		ctx = context.WithValue(ctx, ID, sess.GetId())  // nolint:staticcheck
		ctx = context.WithValue(ctx, Login, sess.GetLogin()) // nolint:staticcheck
		ctx = context.WithValue(ctx, Role, sess.GetRole())   // nolint:staticcheck

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}