# OpenID Connect 

This package intends to simplify RS256 token signing with a openid connect provider with an enabled JWKS endpoint to verify signin keys. At Revas we use Auth0 as identity provider and this library is inspired by auth0 node library https://github.com/auth0/node-jwks-rsa with some Revas style structures. This is a library to retrieve RSA public keys from a JWKS endpoint.

This library also have an extension for go-kit services to provide a ready to use endpoint middleware.

## Usage

See the example_test.go file for usage instructions.
