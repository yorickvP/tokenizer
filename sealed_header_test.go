package tokenizer

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/crypto/nacl/box"
)

func TestSealedHeaders(t *testing.T) {
	isolateUpstreamTrust(t)

	var hits atomic.Int32
	appServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		echo.ServeHTTP(w, r)
	}))
	defer appServer.Close()
	UpstreamTrust.AddCert(appServer.Certificate())
	appHost := appServer.Listener.Addr().String()

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkzServer := httptest.NewServer(NewTokenizer(openKey, AllowPrivateUpstreams()))
	defer tkzServer.Close()

	auth := "trustno1"
	token := "supersecret"
	seal := func(pc ProcessorConfig) string {
		s, err := (&Secret{
			AuthConfig:        NewBearerAuthConfig(auth),
			ProcessorConfig:   pc,
			RequestValidators: []RequestValidator{AllowHosts(appHost)},
		}).Seal(sealKey)
		assert.NoError(t, err)
		return s
	}
	bearerSecret := seal(&InjectProcessorConfig{Token: token})
	apiKeySecret := seal(&InjectProcessorConfig{
		Token:        token,
		FmtProcessor: FmtProcessor{Fmt: "%s"},
		DstProcessor: DstProcessor{Dst: "X-Api-Key"},
	})

	client, err := Client(tkzServer.URL, WithAuth(auth))
	assert.NoError(t, err)
	noAuthClient, err := Client(tkzServer.URL)
	assert.NoError(t, err)

	newReq := func(t *testing.T, host string, hdr http.Header) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		assert.NoError(t, err)
		req.Header = hdr
		return req
	}

	for _, tc := range []struct {
		name string
		hdr  http.Header
		want http.Header
	}{
		{"Authorization with Bearer scheme",
			http.Header{"Authorization": {"Bearer tkz1:" + bearerSecret}},
			http.Header{"Authorization": {"Bearer " + token}}},
		{"Authorization with token scheme",
			http.Header{"Authorization": {"token tkz1:" + bearerSecret}},
			http.Header{"Authorization": {"Bearer " + token}}},
		{"Authorization without scheme",
			http.Header{"Authorization": {"tkz1:" + bearerSecret}},
			http.Header{"Authorization": {"Bearer " + token}}},
		{"X-Api-Key with sealed dst",
			http.Header{"X-Api-Key": {"tkz1:" + apiKeySecret}},
			http.Header{"X-Api-Key": {token}}},
		{"X-Api-Key is stripped when dst differs",
			http.Header{"X-Api-Key": {"tkz1:" + bearerSecret}},
			http.Header{"Authorization": {"Bearer " + token}}},
		{"alongside Proxy-Tokenizer",
			http.Header{"X-Api-Key": {"tkz1:" + apiKeySecret}, headerProxyTokenizer: {bearerSecret}},
			http.Header{"X-Api-Key": {token}, "Authorization": {"Bearer " + token}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, &echoResponse{Headers: tc.want, Body: ""}, doEcho(t, client, newReq(t, appHost, tc.hdr)))
		})
	}

	for _, tc := range []struct {
		name   string
		client *http.Client
		host   string
		hdr    http.Header
		status int
	}{
		{"unmarked Authorization is not a secret", client, appHost,
			http.Header{"Authorization": {"Bearer " + bearerSecret}}, http.StatusBadRequest},
		{"marked value that doesn't unseal", client, appHost,
			http.Header{"Authorization": {"Bearer tkz1:Zm9v"}}, http.StatusBadGateway},
		{"no request-time params", client, appHost,
			http.Header{"Authorization": {"Bearer tkz1:" + bearerSecret + `; {"dst":"X-Leak"}`}}, http.StatusBadGateway},
		{"still needs proxy auth", noAuthClient, appHost,
			http.Header{"Authorization": {"Bearer tkz1:" + bearerSecret}}, http.StatusProxyAuthRequired},
		{"still checks allowed hosts", client, strings.Replace(appHost, "127.0.0.1", "localhost", 1),
			http.Header{"Authorization": {"Bearer tkz1:" + bearerSecret}}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			resp, err := tc.client.Do(newReq(t, tc.host, tc.hdr))
			assert.NoError(t, err)
			assert.Equal(t, tc.status, resp.StatusCode)
			assert.Equal(t, before, hits.Load())
		})
	}

	t.Run("open proxy passes unmarked Authorization through", func(t *testing.T) {
		tkzServer := httptest.NewServer(NewTokenizer(openKey, AllowPrivateUpstreams(), OpenProxy()))
		defer tkzServer.Close()
		client, err := Client(tkzServer.URL)
		assert.NoError(t, err)
		hdr := http.Header{"Authorization": {"Bearer real-key"}}
		assert.Equal(t, &echoResponse{Headers: hdr, Body: ""}, doEcho(t, client, newReq(t, appHost, hdr.Clone())))
	})

	// The SigV4 processor reads the client's own Authorization header, which
	// isn't marked and so must be left alone.
	t.Run("SigV4 Authorization alongside marked X-Api-Key", func(t *testing.T) {
		clientSig := "AWS4-HMAC-SHA256 Credential=AccessKey/20260304/region/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=792ff6fc18a10db6bc1ae6a8f9ffb0caf1432da8d2008e33203a9a0434cd9127"
		sigv4Secret := seal(&Sigv4ProcessorConfig{AccessKey: "AccessKey", SecretKey: "SecretKey", NoSwap: true})
		resp := doEcho(t, client, newReq(t, appHost, http.Header{
			"Authorization": {clientSig},
			"X-Api-Key":     {"tkz1:" + sigv4Secret},
		}))
		got := resp.Headers.Get("Authorization")
		assert.True(t, strings.HasPrefix(got, "AWS4-HMAC-SHA256 Credential=AccessKey/20260304/region/service/aws4_request, "), got)
		assert.NotEqual(t, clientSig, got)
		assert.Zero(t, resp.Headers.Values("X-Api-Key"))
	})
}
