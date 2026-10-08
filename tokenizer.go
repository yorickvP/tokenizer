package tokenizer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/exp/maps"

	"github.com/superfly/flysrc-go"
)

var FilteredHeaders = []string{headerProxyAuthorization, headerProxyTokenizer}

// UpstreamTrust is the trusted certificate pool to use for upstream requests.
var UpstreamTrust *x509.CertPool

func init() {
	var err error
	UpstreamTrust, err = x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
}

const headerProxyTokenizer = "Proxy-Tokenizer"

type tokenizer struct {
	*goproxy.ProxyHttpServer

	// OpenProxy dictates whether requests without any sealed secrets are allowed.
	OpenProxy bool

	// RequireFlySrc will reject requests without a fly-src when set.
	RequireFlySrc bool

	// connectCA, if set, enables CONNECT for clients that only speak
	// HTTPS_PROXY. Tunnels are TLS-terminated with leaf certificates signed by
	// this CA and every tunneled request is pinned to the CONNECT target.
	connectCA *tls.Certificate

	// allowPrivateUpstreams disables the denial of private, loopback,
	// unspecified, link-local, and fdaa::/8 upstream addresses. Only for tests.
	allowPrivateUpstreams bool

	// tokenizerHostnames is a list of hostnames where tokenizer can be reached.
	// If provided, this allows tokenizer to transparently proxy requests (ie.
	// accept normal HTTP requests with arbitrary hostnames) while blocking
	// circular requests back to itself. Any DNS names for tokenizer as well as
	// static IP addresses should be included.
	tokenizerHostnames []string

	priv *[32]byte
	pub  *[32]byte

	flysrcParser *flysrc.Parser
}

func (t *tokenizer) GetFlysrcParser() *flysrc.Parser {
	return t.flysrcParser
}

type Option func(*tokenizer)

// OpenProxy specifies that requests without any sealed secrets are allowed.
func OpenProxy() Option {
	return func(t *tokenizer) {
		t.OpenProxy = true
	}
}

// ConnectMITM enables CONNECT for clients that only speak HTTPS_PROXY. The
// tunnel's TLS is terminated with certificates signed by ca, which clients must
// trust. A tunneled request must name the CONNECT target in its Host header and
// URL. It's validated against and sent to that target, never anything else.
func ConnectMITM(ca tls.Certificate) Option {
	return func(t *tokenizer) {
		t.connectCA = &ca
	}
}

// AllowPrivateUpstreams permits dialing private, loopback, unspecified,
// link-local, and fdaa::/8 upstream addresses. Only for tests that run their
// upstream on loopback.
func AllowPrivateUpstreams() Option {
	return func(t *tokenizer) {
		t.allowPrivateUpstreams = true
	}
}

// RequireFlySrc specifies that requests without a fly-src will be rejected.
func RequireFlySrc() Option {
	return func(t *tokenizer) {
		t.RequireFlySrc = true
	}
}

// WithFlysrcParser specifies a preconfigured flysrc parser to use instead of the
// default flysrc parser.
func WithFlysrcParser(parser *flysrc.Parser) Option {
	return func(t *tokenizer) {
		t.flysrcParser = parser
	}
}

// TokenizerHostnames is a list of hostnames where tokenizer can be reached. If
// provided, this allows tokenizer to transparently proxy requests (ie. accept
// normal HTTP requests with arbitrary hostnames) while blocking circular
// requests back to itself. Any DNS names for tokenizer as well as static IP
// addresses should be included.
func TokenizerHostnames(hostnames ...string) Option {
	return func(t *tokenizer) {
		t.tokenizerHostnames = hostnames
	}
}

func ParseOpenKey(openKey string) (*[32]byte, *[32]byte, error) {
	privBytes, err := hex.DecodeString(openKey)
	if err != nil {
		return nil, nil, fmt.Errorf("bad private key")
	}
	if len(privBytes) != 32 {
		return nil, nil, fmt.Errorf("bad private key size: %d", len(privBytes))
	}
	priv := (*[32]byte)(privBytes)
	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, priv)
	return priv, pub, nil
}

func NewTokenizer(openKey string, opts ...Option) *tokenizer {
	priv, pub, err := ParseOpenKey(openKey)
	if err != nil {
		logrus.WithError(err).Panic(err.Error())
	}

	proxy := goproxy.NewProxyHttpServer()
	tkz := &tokenizer{ProxyHttpServer: proxy, priv: priv, pub: pub, flysrcParser: nil}

	for _, opt := range opts {
		opt(tkz)
	}

	if tkz.RequireFlySrc && tkz.flysrcParser == nil {
		logrus.Panic("FlySrc is required but no flysrc Parser is specified")
	}

	hostnameMap := map[string]bool{}
	for _, hostname := range tkz.tokenizerHostnames {
		hostnameMap[hostname] = true
	}

	// fly-proxy rewrites incoming requests to not include the full URI so we
	// have to look at the host header.
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case len(hostnameMap) == 0:
			logrus.WithFields(reqLogFields(r)).Warn("I'm not that kind of server")
			http.Error(w, "I'm not that kind of server", 400)
			return
		case r.Host == "":
			logrus.WithFields(reqLogFields(r)).Warn("must specify host")
			http.Error(w, "must specify host", 400)
			return
		}

		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			if strings.Contains(err.Error(), "missing port in address") {
				host = r.Host
			} else {
				logrus.WithFields(reqLogFields(r)).Warn("bad host")
				http.Error(w, "bad host", 400)
				return
			}
		}

		if hostnameMap[host] {
			logrus.WithFields(reqLogFields(r)).Warn("circular request")
			http.Error(w, "circular request", 400)
			return
		}

		r.URL.Scheme = "http"
		r.URL.Host = r.Host
		tkz.ServeHTTP(w, r)
	})

	proxy.Tr = &http.Transport{
		Dial: dialFunc(tkz.tokenizerHostnames, tkz.allowPrivateUpstreams),
		// probably not necessary, but I don't want to worry about desync/smuggling
		DisableKeepAlives: true,
	}
	proxy.ConnectDial = nil
	proxy.ConnectDialWithReq = nil
	proxy.OnRequest().HandleConnectFunc(tkz.HandleConnect)
	proxy.OnRequest().DoFunc(tkz.HandleRequest)
	proxy.OnResponse().DoFunc(tkz.HandleResponse)
	// goproxy's TLS MITM loop reads resp.Request, which errorResponse leaves
	// nil.
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil && resp.Request == nil {
			resp.Request = ctx.Req
		}
		return resp
	})

	return tkz
}

func (t *tokenizer) SealKey() string {
	return hex.EncodeToString(t.pub[:])
}

// data that we can pass around between callbacks
type proxyUserData struct {
	// responseProcessors are invoked in HandleResponse to transform the
	// upstream response before returning it to the caller. Currently only
	// JWTProcessorConfig uses this to seal the access token.
	responseProcessors []func(*http.Response) error

	// connectHost is the CONNECT target if this is a tunneled connection,
	// lowercased and without the port if it's 443.
	connectHost string

	// connectHeader holds the CONNECT request's Proxy-Tokenizer and
	// Proxy-Authorization headers, which apply to every tunneled request.
	connectHeader http.Header

	// start time of the current request. gets reset between requests within a
	// tunneled connection.
	requestStart time.Time
	reqLog       logrus.FieldLogger
}

// HandleConnect implements goproxy.FuncHttpsHandler. CONNECT is refused unless
// ConnectMITM is set: request validators check the Host header, but a tunneled
// request is delivered to whatever the CONNECT line named, so honoring CONNECT
// without pinning each request to the CONNECT target (see pinToConnectTarget)
// would let a client use a host-scoped secret against a different host.
func (t *tokenizer) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	logger := logrus.WithField("connect_host", host).WithFields(reqLogFields(ctx.Req))
	if t.connectCA == nil {
		logger.Warn("CONNECT not supported")
		ctx.Resp = errorResponse(ErrBadRequest)
		return goproxy.RejectConnect, ""
	}

	hostname, _, err := net.SplitHostPort(host)
	if err != nil || hostname == "" {
		logger.Warn("bad CONNECT host")
		ctx.Resp = errorResponse(ErrBadRequest)
		return goproxy.RejectConnect, ""
	}
	if slices.ContainsFunc(t.tokenizerHostnames, func(h string) bool { return strings.EqualFold(h, hostname) }) {
		logger.Warn("circular request")
		ctx.Resp = errorResponse(ErrBadRequest)
		return goproxy.RejectConnect, ""
	}

	connectHeader := make(http.Header)
	for _, h := range FilteredHeaders {
		if vs := ctx.Req.Header.Values(h); len(vs) > 0 {
			connectHeader[h] = vs
		}
	}

	ctx.UserData = &proxyUserData{
		connectHost:   canonicalHost(host),
		connectHeader: connectHeader,
	}

	return &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(t.connectCA),
	}, host
}

// pinToConnectTarget makes a request read from a CONNECT tunnel name the
// CONNECT target in both req.Host, which request validators check, and
// req.URL, which the transport dials. goproxy builds req.URL from the CONNECT
// line but leaves req.Host as the client sent it, and an absolute-form request
// line inside the tunnel can name any URL, so both must match the target.
func pinToConnectTarget(req *http.Request, pud *proxyUserData) error {
	// goproxy's MITM websocket path dials upstream itself, bypassing dialFunc
	// and verifying no certificates.
	if req.Header.Get("Upgrade") != "" {
		return fmt.Errorf("%w: upgrade not supported in CONNECT tunnel", ErrBadRequest)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%w: %s URL in CONNECT tunnel", ErrBadRequest, req.URL.Scheme)
	}

	if canonicalHost(req.Host) != pud.connectHost || canonicalHost(req.URL.Host) != pud.connectHost {
		return fmt.Errorf("%w: request for %s in CONNECT tunnel to %s", ErrBadRequest, req.Host, pud.connectHost)
	}

	req.Host = pud.connectHost
	// dialFunc upgrades upstream connections to TLS.
	req.URL.Scheme = "http"
	req.URL.Host = pud.connectHost

	for h, vs := range pud.connectHeader {
		if len(req.Header.Values(h)) == 0 {
			req.Header[h] = vs
		}
	}

	return nil
}

// canonicalHost lowercases a host[:port] and drops the port if it's 443.
func canonicalHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, ":443"))
}

// tunnelRoundTrip turns transport errors into responses for tunneled requests.
// goproxy's MITM loop drops the client connection on error, which would leave
// the client without a reason.
func tunnelRoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	resp, err := ctx.Proxy.Tr.RoundTrip(req)
	if err != nil {
		if pud, ok := ctx.UserData.(*proxyUserData); ok && pud.reqLog != nil {
			pud.reqLog = pud.reqLog.WithError(err)
		}
		resp = errorResponse(err)
		resp.Request = req
	}
	return resp, nil
}

func getSource(req *http.Request) string {
	var forwards []string
	if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		forwards = strings.Split(forwardedFor, ", ")
	}

	srcs := append(forwards, req.RemoteAddr)
	return strings.Join(srcs, ", ")
}

func reqLogFields(req *http.Request) logrus.Fields {
	return logrus.Fields{
		"source":    getSource(req),
		"method":    req.Method,
		"host":      req.Host,
		"path":      req.URL.Path,
		"queryKeys": strings.Join(maps.Keys(req.URL.Query()), ", "),
	}
}

// HandleRequest implements goproxy.FuncReqHandler
func (t *tokenizer) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if ctx.UserData == nil {
		ctx.UserData = &proxyUserData{}
	}
	pud, ok := ctx.UserData.(*proxyUserData)

	if !ok || !pud.requestStart.IsZero() || pud.reqLog != nil {
		logrus.Warn("bad proxyUserData")
		return nil, errorResponse(ErrInternal)
	}

	pud.requestStart = time.Now()
	if req.URL == nil {
		// goproxy's TLS MITM loop hands us a nil URL when it can't parse the
		// request target, e.g. asterisk-form "OPTIONS *" inside the tunnel.
		pud.reqLog = logrus.WithField("connect_host", pud.connectHost)
		pud.reqLog.Warn("bad URL")
		return nil, errorResponse(ErrBadRequest)
	}
	pud.reqLog = logrus.WithFields(reqLogFields(ctx.Req))

	if pud.connectHost != "" {
		pud.reqLog = pud.reqLog.WithField("connect_host", pud.connectHost)
		if err := pinToConnectTarget(req, pud); err != nil {
			pud.reqLog.WithError(err).Warn("tunneled request")
			return nil, errorResponse(err)
		}
		ctx.RoundTripper = goproxy.RoundTripperFunc(tunnelRoundTrip)
	}

	if t.flysrcParser != nil {
		src, err := t.flysrcParser.FromRequest(req)
		if err != nil {
			if t.RequireFlySrc {
				pud.reqLog.Warn(err.Error())
				return nil, errorResponse(ErrBadRequest)
			}
		} else {
			pud.reqLog = pud.reqLog.WithFields(logrus.Fields{
				"flysrc-org":       src.Org,
				"flysrc-app":       src.App,
				"flysrc-instance":  src.Instance,
				"flysrc-timestamp": src.Timestamp,
			})
		}
	}

	var processors []RequestProcessor
	reqResult, err := t.processorsFromRequest(req)
	if len(reqResult.safeSecrets) > 0 {
		pud.reqLog = pud.reqLog.WithField("secrets", reqResult.safeSecrets)
	}
	if err != nil {
		pud.reqLog.WithError(err).Warn("find processor")
		return req, errorResponse(err)
	} else {
		processors = append(processors, reqResult.request...)
		pud.responseProcessors = append(pud.responseProcessors, reqResult.response...)
	}

	if len(processors) == 0 && !t.OpenProxy {
		pud.reqLog.Warn("no processors")
		return nil, errorResponse(ErrBadRequest)
	}

	pud.reqLog = pud.reqLog.WithField("processors", len(processors))

	for _, processor := range processors {
		if err := processor(req); err != nil {
			pud.reqLog.WithError(err).Warn("run processor")
			return nil, errorResponse(ErrBadRequest)
		}
	}

	for _, h := range FilteredHeaders {
		req.Header.Del(h)
	}

	return req, nil
}

// HandleResponse implements goproxy.FuncRespHandler
func (t *tokenizer) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	// This callback is hit twice if there was an error in the downstream
	// request. The first time a nil request is given and the second time we're
	// given whatever we returned the first time. Skip logging on the second
	// call. This should continue to work okay if
	// https://github.com/elazarl/goproxy/pull/512 is ever merged.
	if ctx.Error != nil && resp != nil {
		return resp
	}

	pud, ok := ctx.UserData.(*proxyUserData)
	if !ok || pud.requestStart.IsZero() || pud.reqLog == nil {
		logrus.Warn("missing proxyUserData")
		return errorResponse(ErrInternal)
	}

	log := pud.reqLog.WithField("durMS", int64(time.Since(pud.requestStart)/time.Millisecond))
	if resp != nil {
		log = log.WithField("status", resp.StatusCode)
		resp.Header.Set("Connection", "close")

		// Run response processors (e.g. JWT token sealing)
		for _, rp := range pud.responseProcessors {
			if err := rp(resp); err != nil {
				log.WithError(err).Warn("run response processor")
				return errorResponse(err)
			}
		}
	}

	// reset pud for next request in tunnel
	pud.requestStart = time.Time{}
	pud.reqLog = nil
	pud.responseProcessors = nil

	if ctx.Error != nil {
		log.WithError(ctx.Error).Warn()
		return errorResponse(ctx.Error)
	}

	log.Info()

	return resp
}

// loggerSecret holds one secret and params from the Proxy-Tokenizer header for logging.
// The secrets are sanitized of their hazmat.
type loggerSecret struct {
	Secret string `json:"secret"`
	Params string `json:"params"`
}

type processorsResult struct {
	request     []RequestProcessor
	response    []func(*http.Response) error
	safeSecrets []loggerSecret
}

// OpenSealed decodes and unseals a sealed token and returns its raw (unparsed) contents.
func (t *tokenizer) OpenSealed(b64Secret string) ([]byte, error) {
	ctSecret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Secret))
	if err != nil {
		return nil, fmt.Errorf("bad Proxy-Tokenizer encoding: %w", err)
	}

	jsonSecret, ok := box.OpenAnonymous(nil, ctSecret, t.pub, t.priv)
	if !ok {
		return nil, errors.New("failed Proxy-Tokenizer decryption")
	}
	return jsonSecret, nil
}

func (t *tokenizer) processorsFromRequest(req *http.Request) (*processorsResult, error) {
	hdrs := req.Header[headerProxyTokenizer]
	result := &processorsResult{
		request: make([]RequestProcessor, 0, len(hdrs)),
	}

	for _, hdr := range hdrs {
		b64Secret, params, err := parseHeaderProxyTokenizer(hdr)
		if err != nil {
			return result, err
		}

		jsonSecret, err := t.OpenSealed(b64Secret)
		if err != nil {
			return result, err
		}

		secret := new(Secret)
		if err = json.Unmarshal(jsonSecret, secret); err != nil {
			return result, fmt.Errorf("bad secret json: %w", err)
		}

		// capture secret and params for logger
		safeSecret := secret.StripHazmatString()
		pstr, _ := json.Marshal(params)
		result.safeSecrets = append(result.safeSecrets, loggerSecret{safeSecret, string(pstr)})

		if err = secret.AuthRequest(t, req); err != nil {
			return result, fmt.Errorf("unauthorized to use secret: %w", err)
		}

		for _, v := range secret.RequestValidators {
			if err := v.Validate(req); err != nil {
				return result, fmt.Errorf("request validator failed: %w", err)
			}
		}

		sealCtx := &SealingContext{
			AuthConfig:        secret.AuthConfig,
			RequestValidators: secret.RequestValidators,
			SealKey:           t.pub,
		}

		processor, err := secret.Processor(params, sealCtx)
		if err != nil {
			return result, err
		}
		result.request = append(result.request, processor)

		// Check if the processor also handles responses
		if rpc, ok := secret.ProcessorConfig.(ResponseProcessorConfig); ok {
			respProc, err := rpc.ResponseProcessor(params, sealCtx)
			if err != nil {
				return result, err
			}
			if respProc != nil {
				result.response = append(result.response, respProc)
			}
		}
	}

	return result, nil
}

func parseHeaderProxyTokenizer(hdr string) (string, map[string]string, error) {
	b64Secret, paramJSON, _ := strings.Cut(hdr, ";")

	b64Secret = strings.TrimFunc(b64Secret, unicode.IsSpace)
	paramJSON = strings.TrimFunc(paramJSON, unicode.IsSpace)

	if b64Secret == "" {
		return "", nil, fmt.Errorf("%w: bad tokenizer header", ErrBadRequest)
	}

	processorParams := make(map[string]string)
	if paramJSON != "" {
		if err := json.Unmarshal([]byte(paramJSON), &processorParams); err != nil {
			return "", nil, fmt.Errorf("%w: %w", ErrBadRequest, err)
		}
	}

	return b64Secret, processorParams, nil
}

func formatHeaderProxyTokenizer(b64Secret string, processorParams map[string]string) string {
	hdr := b64Secret

	if len(processorParams) > 0 {
		paramJSON, _ := json.Marshal(processorParams)
		hdr = fmt.Sprintf("%s; %s", hdr, paramJSON)
	}

	return hdr
}

func errorResponse(err error) *http.Response {
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, ErrNotAuthorized):
		status = http.StatusProxyAuthRequired
	case errors.Is(err, ErrBadRequest):
		status = http.StatusBadRequest
	case errors.Is(err, ErrInternal):
		status = http.StatusBadGateway
	}

	return &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(err.Error()))),
		Header:     make(http.Header),
	}
}

// dialFunc returns a function for dialing network addresses. Ours does a few
// special things.
//   - It denies connections to private, loopback, unspecified, link-local, and
//     fdaa::/8 addresses unless allowPrivate is set.
//   - It denies connections to the given set of IP addresses. This is to prevent
//     circular requests back to tokenizer. Invalid IPs are ignored.
//   - It rejects requests for TLS upstreams. We need to see/modify requests, so
//     our proxy can't do passthrough TLS.
//   - It forces the upstream connection to be TLS. We want the actual upstream
//     connection to be over TLS because security.
func dialFunc(badAddrs []string, allowPrivate bool) func(string, string) (net.Conn, error) {
	_, fdaaNet, err := net.ParseCIDR("fdaa::/8")
	if err != nil {
		panic(err)
	}

	netDialer := net.Dialer{}

	baMap := map[string]bool{}
	for _, ba := range badAddrs {
		if ip := net.ParseIP(ba); ip != nil {
			baMap[ip.String()] = true
		}
	}

	netDialer.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
		h, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}

		switch ip := net.ParseIP(h); {
		case ip == nil:
			return fmt.Errorf("bad ip: %s", address)
		case baMap[ip.String()]:
			return fmt.Errorf("%w: dialing address %s denied", ErrBadRequest, address)
		case allowPrivate:
			return nil
		case ip.IsPrivate():
			return fmt.Errorf("%w: dialing private address %s denied", ErrBadRequest, address)
		case ip.IsLoopback():
			return fmt.Errorf("%w: dialing loopback address %s denied", ErrBadRequest, address)
		case ip.IsUnspecified():
			return fmt.Errorf("%w: dialing unspecified address %s denied", ErrBadRequest, address)
		case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
			return fmt.Errorf("%w: dialing link-local address %s denied", ErrBadRequest, address)
		case fdaaNet.Contains(ip):
			return fmt.Errorf("%w: dialing fdaa::/8 address %s denied", ErrBadRequest, address)
		default:
			return nil
		}
	}

	return func(network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("%w: dialing network %s not supported", ErrBadRequest, network)
		}

		hostname, port, _ := strings.Cut(addr, ":")
		if hostname == "" {
			return nil, fmt.Errorf("%w: attempt to dial without host: %q", ErrBadRequest, addr)
		}
		switch port {
		case "443":
			return nil, fmt.Errorf("%w: proxied request must be HTTP", ErrBadRequest)
		case "80", "":
			port = "443"
		}
		addr = fmt.Sprintf("%s:%s", hostname, port)

		return tls.DialWithDialer(&netDialer, network, addr, &tls.Config{RootCAs: UpstreamTrust})
	}
}
