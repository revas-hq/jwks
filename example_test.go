package jwks_test

import (
	"context"
	"net/url"

	stdjwt "github.com/dgrijalva/jwt-go"
	kitjwt "github.com/go-kit/kit/auth/jwt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	jwks "github.com/revas-hq/go-jwks"
)

func Example() {
	url, _ := url.Parse("https://revas-os.eu.auth0.com/.well-known/jwks.json")
	c := jwks.NewDefaultClient(url)
	ctx := context.Background()
	keyFunc := func(token *stdjwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "Invalid kid")
		}
		return c.GetPublicKey(ctx, kid)
	}
	_ = kitjwt.NewParser(keyFunc, stdjwt.SigningMethodRS256, kitjwt.MapClaimsFactory)
}
