package jwks

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	stdjwk "github.com/lestrrat-go/jwx/jwk"

	kitendpoint "github.com/go-kit/kit/endpoint"
	kitrate "github.com/go-kit/kit/ratelimit"
	kithttp "github.com/go-kit/kit/transport/http"

	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrUnavailableKeysEndpoint = status.Error(codes.Internal, "signing keys endpoint is unavailable")
	ErrInvalidKeysEndpoint     = status.Error(codes.Internal, "signing keys endpoint is misconfigured")
	ErrKeyNotFound             = status.Error(codes.NotFound, "no signing key found")
)

func NewGetKeysFileEndpoint(path string) kitendpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return stdjwk.ParseReader(f)
	}
}

func NewGetKeysClientEndpoint(url *url.URL) kitendpoint.Endpoint {
	return kithttp.NewClient(
		"GET",
		url,
		func(context.Context, *http.Request, interface{}) error { return nil },
		func(_ context.Context, r *http.Response) (interface{}, error) {
			return stdjwk.ParseReader(r.Body)
		},
	).Endpoint()
}

func NewLimiterMiddleware() kitendpoint.Middleware {
	l := rate.NewLimiter(rate.Every(time.Minute/10), 1)
	return kitrate.NewErroringLimiter(l)
}

func NewCacheMiddleware() kitendpoint.Middleware {
	mu := sync.Mutex{}
	c := cache.New(48*time.Hour, 48*time.Hour)
	return func(next kitendpoint.Endpoint) kitendpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			r, ok := c.Get("jwks")
			if ok {
				return r, nil
			}
			mu.Lock()
			defer mu.Unlock()
			r, ok = c.Get("jwks")
			if ok {
				return r, nil
			}
			r, err := next(ctx, request)
			if err != nil {
				return nil, err
			}
			c.Set("jwks", r, cache.DefaultExpiration)
			return r, nil
		}
	}
}

func GetPublicKey(endpoint kitendpoint.Endpoint, ctx context.Context, kid string) (interface{}, error) {
	r, err := endpoint(ctx, nil)
	if err != nil {
		return nil, ErrUnavailableKeysEndpoint
	}
	keys, ok := r.(stdjwk.Set)
	if !ok {
		return nil, ErrInvalidKeysEndpoint
	}
	key, ok := keys.LookupKeyID(kid)
	if !ok || key.KeyUsage() != "sig" {
		return nil, ErrKeyNotFound
	}
	certs := key.X509CertChain()
	if len(certs) == 0 {
		return nil, ErrKeyNotFound
	}
	return certs[0].PublicKey, nil
}
