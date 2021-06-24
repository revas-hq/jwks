package jwks_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	jwks "github.com/revas-hq/go-jwks"
)

func TestShouldErrorWithUnavailableKeys(t *testing.T) {
	url, _ := url.Parse("https://example.com/.well-known/jwks.json")
	c := jwks.NewDefaultClient(url)
	_, err := c.GetPublicKey(context.Background(), "kid-value")
	if err != jwks.ErrUnavailableKeysEndpoint {
		t.Fatalf("got %v, want %v", err, jwks.ErrUnavailableKeysEndpoint)
	}

	e := jwks.NewGetKeysClientEndpoint(url)
	c = jwks.NewClient(e)
	_, err = c.GetPublicKey(context.Background(), "kid-value")
	if err != jwks.ErrUnavailableKeysEndpoint {
		t.Fatalf("got %v, want %v", err, jwks.ErrUnavailableKeysEndpoint)
	}

	e = jwks.NewGetKeysFileEndpoint("invalid-file.json")
	c = jwks.NewClient(e)
	_, err = c.GetPublicKey(context.Background(), "kid-value")
	if err != jwks.ErrUnavailableKeysEndpoint {
		t.Fatalf("got %v, want %v", err, jwks.ErrUnavailableKeysEndpoint)
	}
}

func TestShouldReturnValidKey(t *testing.T) {
	data, err := ioutil.ReadFile("./jwks_data.json")
	if err != nil {
		t.Fatalf("got %v, want %v", err, nil)
	}
	var ops uint64
	s := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		atomic.AddUint64(&ops, 1)
		res.WriteHeader(http.StatusOK)
		res.Write(data)
	}))
	url, _ := url.Parse(s.URL)
	c := jwks.NewDefaultClient(url)

	_, err = c.GetPublicKey(context.Background(), "u8EE81G1hj3-i5FBtMEIa")
	if err != nil {
		t.Fatalf("got %v, want %v", err, nil)
	}

	_, err = c.GetPublicKey(context.Background(), "invalid-kid")
	if err != jwks.ErrKeyNotFound {
		t.Fatalf("got %v, want %v", err, jwks.ErrKeyNotFound)
	}

	if ops != 1 {
		t.Fatalf("got %v, want %v", ops, 1)
	}
}

func TestShouldCallEndpointOnce(t *testing.T) {
	data, err := ioutil.ReadFile("./jwks_data.json")
	if err != nil {
		t.Fatalf("got %v, want %v", err, nil)
	}
	var ops uint64
	s := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		atomic.AddUint64(&ops, 1)
		res.WriteHeader(http.StatusOK)
		res.Write(data)
	}))
	url, _ := url.Parse(s.URL)
	c := jwks.NewDefaultClient(url)

	wg := sync.WaitGroup{}
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			c.GetPublicKey(context.Background(), "u8EE81G1hj3-i5FBtMEIa")
			wg.Done()
		}()
	}
	wg.Wait()

	if ops != 1 {
		t.Fatalf("got %v, want %v", ops, 1)
	}
}
