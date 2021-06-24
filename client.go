package jwks

import (
	"context"
	"net/url"

	kitendpoint "github.com/go-kit/kit/endpoint"
)

type Client interface {
	GetPublicKey(ctx context.Context, kid string) (interface{}, error)
}

type client struct {
	endpoint kitendpoint.Endpoint
}

func NewDefaultClient(jwks *url.URL) Client {
	e := NewGetKeysClientEndpoint(jwks)
	e = NewLimiterMiddleware()(e)
	e = NewCacheMiddleware()(e)
	return &client{
		endpoint: e,
	}
}

func NewClient(endpoint kitendpoint.Endpoint) Client {
	e := endpoint
	e = NewLimiterMiddleware()(e)
	e = NewCacheMiddleware()(e)
	return &client{
		endpoint: e,
	}
}

func (c *client) GetPublicKey(ctx context.Context, kid string) (interface{}, error) {
	return GetPublicKey(c.endpoint, ctx, kid)
}
