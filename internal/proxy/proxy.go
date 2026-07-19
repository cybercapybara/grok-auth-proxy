package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/moveeeax/grok-auth-proxy/internal/auth"
	"github.com/moveeeax/grok-auth-proxy/internal/middleware"
	"github.com/moveeeax/grok-auth-proxy/internal/store"
)

// TokenProvider supplies upstream access tokens.
type TokenProvider interface {
	GetAccessToken(ctx context.Context) (string, error)
	ForceRefresh(ctx context.Context) error
}

// Auditor records proxied requests for admin audit.
type Auditor interface {
	InsertAuditLog(row *store.AuditLog) error
}

// Upstream reverse-proxies OpenAI-compatible requests to xAI.
type Upstream struct {
	base         *url.URL
	httpClient   *http.Client
	tokens       TokenProvider
	log          *zap.Logger
	auditor      Auditor
	auditEnabled bool
	maxBody      int
}

// Options configures Upstream.
type Options struct {
	BaseURL      string
	Tokens       TokenProvider
	Log          *zap.Logger
	Auditor      Auditor
	AuditEnabled bool
	MaxBodyBytes int
}

// New creates an Upstream proxy.
func New(baseURL string, tokens TokenProvider, log *zap.Logger) (*Upstream, error) {
	return NewWithOptions(Options{BaseURL: baseURL, Tokens: tokens, Log: log})
}

// NewWithOptions creates an Upstream with audit settings.
func NewWithOptions(opts Options) (*Upstream, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base: %w", err)
	}
	if opts.Log == nil {
		opts.Log = zap.NewNop()
	}
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 65536
	}
	return &Upstream{
		base: u,
		httpClient: &http.Client{
			// No overall Timeout: streaming requests can run long.
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ResponseHeaderTimeout: 120 * time.Second,
			},
		},
		tokens:       opts.Tokens,
		log:          opts.Log,
		auditor:      opts.Auditor,
		auditEnabled: opts.AuditEnabled && opts.Auditor != nil,
		maxBody:      maxBody,
	}, nil
}

// Handler proxies the current request path to the upstream (e.g. /v1/chat/completions).
func (u *Upstream) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := u.forward(c, false); err != nil {
			u.log.Error("proxy error", zap.Error(err), zap.String("path", c.Request.URL.Path))
			if !c.Writer.Written() {
				c.JSON(http.StatusBadGateway, gin.H{
					"error": gin.H{"message": "upstream request failed", "type": "api_error"},
				})
			}
		}
	}
}

func (u *Upstream) forward(c *gin.Context, retried bool) error {
	start := time.Now()
	reqBody, reqTrunc, err := readLimited(c.Request.Body, u.maxBody)
	if err != nil {
		return err
	}
	_ = c.Request.Body.Close()
	c.Request.Body = io.NopCloser(bytes.NewReader(reqBody))

	token, err := u.tokens.GetAccessToken(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{"message": "upstream authentication unavailable", "type": "api_error"},
		})
		u.recordAudit(c, start, reqBody, reqTrunc, nil, false, http.StatusServiceUnavailable, err)
		return err
	}

	target := u.buildURL(c.Request.URL)
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	copyHeaders(req.Header, c.Request.Header)
	// Never forward client credentials; inject Grok token.
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Del("Host")
	req.Host = u.base.Host
	if len(reqBody) > 0 {
		req.ContentLength = int64(len(reqBody))
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		u.recordAudit(c, start, reqBody, reqTrunc, nil, false, 0, err)
		return err
	}

	// On 401, try one forced refresh + retry.
	if resp.StatusCode == http.StatusUnauthorized && !retried {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if rerr := u.tokens.ForceRefresh(c.Request.Context()); rerr != nil {
			u.log.Warn("force refresh after 401 failed", zap.Error(rerr))
			c.JSON(http.StatusBadGateway, gin.H{
				"error": gin.H{"message": "upstream unauthorized", "type": "api_error"},
			})
			u.recordAudit(c, start, reqBody, reqTrunc, nil, false, http.StatusBadGateway, rerr)
			return rerr
		}
		return u.forward(c, true)
	}
	defer resp.Body.Close()

	filterResponseHeaders(c.Writer.Header(), resp.Header)
	c.Status(resp.StatusCode)

	// Stream body with flushing for SSE; tee into limited buffer for audit.
	var respBuf bytes.Buffer
	respTrunc := false
	flusher, canFlush := c.Writer.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := c.Writer.Write(buf[:n]); werr != nil {
				u.recordAudit(c, start, reqBody, reqTrunc, respBuf.Bytes(), respTrunc, resp.StatusCode, werr)
				return werr
			}
			if canFlush {
				flusher.Flush()
			}
			if u.auditEnabled {
				remain := u.maxBody - respBuf.Len()
				if remain > 0 {
					if n <= remain {
						_, _ = respBuf.Write(buf[:n])
					} else {
						_, _ = respBuf.Write(buf[:remain])
						respTrunc = true
					}
				} else {
					respTrunc = true
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				u.recordAudit(c, start, reqBody, reqTrunc, respBuf.Bytes(), respTrunc, resp.StatusCode, nil)
				return nil
			}
			u.recordAudit(c, start, reqBody, reqTrunc, respBuf.Bytes(), respTrunc, resp.StatusCode, readErr)
			return readErr
		}
	}
}

func (u *Upstream) recordAudit(
	c *gin.Context,
	start time.Time,
	reqBody []byte,
	reqTrunc bool,
	respBody []byte,
	respTrunc bool,
	status int,
	callErr error,
) {
	if !u.auditEnabled || u.auditor == nil {
		return
	}

	row := &store.AuditLog{
		RequestID:         c.GetString(middleware.ContextRequestID),
		Method:            c.Request.Method,
		Path:              c.Request.URL.Path,
		Query:             c.Request.URL.RawQuery,
		ClientIP:          c.ClientIP(),
		UserAgent:         c.Request.UserAgent(),
		StatusCode:        status,
		LatencyMS:         time.Since(start).Milliseconds(),
		RequestBody:       string(reqBody),
		ResponseBody:      string(respBody),
		RequestTruncated:  reqTrunc,
		ResponseTruncated: respTrunc,
		Stream:            detectStream(reqBody),
		Model:             extractModel(reqBody),
	}
	if callErr != nil {
		row.Error = callErr.Error()
	}
	if v, ok := c.Get(middleware.ContextAPIKey); ok {
		if key, ok := v.(*store.APIKey); ok && key != nil {
			row.APIKeyID = key.ID
			row.APIKeyName = key.Name
			row.APIKeyPrefix = key.KeyPrefix
		}
	}

	// Async insert so streaming clients are not blocked on DB.
	go func() {
		if err := u.auditor.InsertAuditLog(row); err != nil {
			u.log.Warn("audit insert failed", zap.Error(err))
		}
	}()
}

func readLimited(r io.Reader, max int) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	if max <= 0 {
		max = 65536
	}
	// Read one extra byte to detect truncation.
	data, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

func extractModel(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	return m.Model
}

func detectStream(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var m struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	return m.Stream
}

func (u *Upstream) buildURL(reqURL *url.URL) string {
	// Preserve path and query; join with upstream base path if any.
	basePath := strings.TrimRight(u.base.Path, "/")
	path := reqURL.Path
	if basePath != "" && !strings.HasPrefix(path, basePath) {
		// base is like https://api.x.ai/v1 and path is /v1/chat/completions
	}
	out := *u.base
	// Client paths are absolute like /v1/chat/completions.
	// If base path is /v1, strip duplicate /v1 from request.
	if basePath == "/v1" && strings.HasPrefix(path, "/v1") {
		out.Path = path
		out.RawQuery = reqURL.RawQuery
		return out.String()
	}
	if basePath != "" && basePath != "/" {
		out.Path = basePath + path
	} else {
		out.Path = path
	}
	out.RawQuery = reqURL.RawQuery
	return out.String()
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		switch strings.ToLower(k) {
		case "authorization", "host", "content-length", "connection", "transfer-encoding":
			continue
		default:
			for _, v := range vals {
				dst.Add(k, v)
			}
		}
	}
}

func filterResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		switch strings.ToLower(k) {
		case "connection", "transfer-encoding", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailers", "upgrade", "set-cookie":
			continue
		default:
			for _, v := range vals {
				dst.Add(k, v)
			}
		}
	}
}

// Ensure auth.Manager implements TokenProvider.
var _ TokenProvider = (*auth.Manager)(nil)
