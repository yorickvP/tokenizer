package tokenizer

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/crypto/nacl/box"
)

func TestConnectMITM(t *testing.T) {
	isolateUpstreamTrust(t)

	appServer := httptest.NewTLSServer(echo)
	defer appServer.Close()
	UpstreamTrust.AddCert(appServer.Certificate())
	appHost := appServer.Listener.Addr().String()

	// evilServer stands in for an attacker-controlled host with a valid cert.
	var evilHits atomic.Int32
	evilServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits.Add(1)
		echo.ServeHTTP(w, r)
	}))
	defer evilServer.Close()
	UpstreamTrust.AddCert(evilServer.Certificate())
	evilHost := evilServer.Listener.Addr().String()

	ca, caPool := testCA(t)

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkz := NewTokenizer(openKey, AllowPrivateUpstreams(), ConnectMITM(ca))
	tkzServer := httptest.NewServer(tkz)
	defer tkzServer.Close()

	auth := "trustno1"
	token := "supersecret"
	secret, err := (&Secret{
		AuthConfig:        NewBearerAuthConfig(auth),
		ProcessorConfig:   &InjectProcessorConfig{Token: token},
		RequestValidators: []RequestValidator{AllowHosts(appHost)},
	}).Seal(sealKey)
	assert.NoError(t, err)

	proxyURL, err := url.Parse(tkzServer.URL)
	assert.NoError(t, err)
	proxyURL.User = url.UserPassword("x", auth)

	t.Run("HTTPS_PROXY client, secret on CONNECT", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			ProxyConnectHeader: http.Header{headerProxyTokenizer: {secret}},
			TLSClientConfig:    &tls.Config{RootCAs: caPool},
		}}
		req, err := http.NewRequest(http.MethodPost, "https://"+appHost+"/foo", nil)
		assert.NoError(t, err)
		for range 2 {
			assert.Equal(t, &echoResponse{
				Headers: http.Header{"Authorization": {"Bearer " + token}},
				Body:    "",
			}, doEcho(t, client, req))
		}
	})

	t.Run("HTTPS_PROXY client, secret in Authorization", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		}}
		req, err := http.NewRequest(http.MethodPost, "https://"+appHost+"/foo", nil)
		assert.NoError(t, err)
		req.Header.Set("Authorization", "Bearer tkz1:"+secret)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {"Bearer " + token}},
			Body:    "",
		}, doEcho(t, client, req))
	})

	t.Run("HTTPS_PROXY client, secret inside tunnel", func(t *testing.T) {
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		}}
		req, err := http.NewRequest(http.MethodPost, "https://"+appHost+"/foo", nil)
		assert.NoError(t, err)
		req.Header.Set(headerProxyTokenizer, secret)
		assert.Equal(t, &echoResponse{
			Headers: http.Header{"Authorization": {"Bearer " + token}},
			Body:    "",
		}, doEcho(t, client, req))
	})

	// tunnel opens a CONNECT tunnel to target carrying the secret and auth and
	// returns the client side of the MITM'd TLS connection.
	tunnel := func(t *testing.T, target string) *tls.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", tkzServer.Listener.Addr().String())
		assert.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s: %s\r\nProxy-Authorization: Bearer %s\r\n\r\n",
			target, target, headerProxyTokenizer, secret, auth)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 0, br.Buffered())
		host, _, _ := net.SplitHostPort(target)
		tconn := tls.Client(conn, &tls.Config{RootCAs: caPool, ServerName: host})
		assert.NoError(t, tconn.Handshake())
		return tconn
	}

	roundTrip := func(t *testing.T, conn *tls.Conn, raw string) *http.Response {
		t.Helper()
		_, err := io.WriteString(conn, raw)
		assert.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		assert.NoError(t, err)
		return resp
	}

	for _, tc := range []struct{ name, target, raw string }{
		// The bug f275cdd closed: the secret is scoped to appHost, the tunnel
		// goes to evilHost.
		{"Host header differs from CONNECT target", evilHost,
			"GET / HTTP/1.1\r\nHost: " + appHost + "\r\n\r\n"},
		{"absolute https URL differs from CONNECT target", evilHost,
			"GET https://" + appHost + "/ HTTP/1.1\r\nHost: " + appHost + "\r\n\r\n"},
		{"absolute https URL to another host", appHost,
			"GET https://" + evilHost + "/ HTTP/1.1\r\nHost: " + appHost + "\r\n\r\n"},
		{"absolute http URL", appHost,
			"GET http://" + evilHost + "/ HTTP/1.1\r\nHost: " + appHost + "\r\n\r\n"},
		// goproxy can't rebuild this URL and passes a nil req.URL.
		{"asterisk-form", appHost,
			"OPTIONS * HTTP/1.1\r\nHost: " + appHost + "\r\n\r\n"},
		// goproxy would dial this itself, unguarded and unverified.
		{"websocket upgrade", appHost,
			"GET / HTTP/1.1\r\nHost: " + appHost + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
				"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := roundTrip(t, tunnel(t, tc.target), tc.raw)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, int32(0), evilHits.Load())
		})
	}

	t.Run("secret pinned to CONNECT target is still validated", func(t *testing.T) {
		resp := roundTrip(t, tunnel(t, evilHost), "GET / HTTP/1.1\r\nHost: "+evilHost+"\r\n\r\n")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, int32(0), evilHits.Load())
	})

	t.Run("CONNECT to tokenizer hostname", func(t *testing.T) {
		tkzServer := httptest.NewServer(NewTokenizer(openKey, AllowPrivateUpstreams(), ConnectMITM(ca), TokenizerHostnames("Tokenizer.internal")))
		defer tkzServer.Close()
		conn, err := net.Dial("tcp", tkzServer.Listener.Addr().String())
		assert.NoError(t, err)
		defer conn.Close()
		io.WriteString(conn, "CONNECT tokenizer.internal:443 HTTP/1.1\r\nHost: tokenizer.internal:443\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("dial guard applies inside tunnel", func(t *testing.T) {
		tkz := NewTokenizer(openKey, ConnectMITM(ca))
		tkzServer := httptest.NewServer(tkz)
		defer tkzServer.Close()
		proxyURL, err := url.Parse(tkzServer.URL)
		assert.NoError(t, err)
		proxyURL.User = url.UserPassword("x", auth)
		client := &http.Client{Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			ProxyConnectHeader: http.Header{headerProxyTokenizer: {secret}},
			TLSClientConfig:    &tls.Config{RootCAs: caPool},
		}}
		resp, err := client.Get("https://" + appHost + "/")
		assert.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, string(body), "dialing loopback address")
	})
}

// isolateUpstreamTrust lets a test add to UpstreamTrust without affecting
// other tests. httptest servers share a certificate, so trusting one trusts
// them all.
func isolateUpstreamTrust(t *testing.T) {
	t.Helper()
	orig := UpstreamTrust
	UpstreamTrust = orig.Clone()
	t.Cleanup(func() { UpstreamTrust = orig })
}

func testCA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tokenizer test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	assert.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
