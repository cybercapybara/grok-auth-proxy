package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/cybercapybara/grok-auth-proxy/internal/auth"
)

// TokenProvider supplies upstream access tokens.
type TokenProvider interface {
	GetAccessToken(ctx context.Context) (string, error)
	ForceRefresh(ctx context.Context) error
}

// Upstream reverse-proxies OpenAI-compatible requests to xAI.
type Upstream struct {
	base       *url.URL
	httpClient *http.Client
	tokens     TokenProvider
	log        *zap.Logger
}

// New creates an Upstream proxy.
func New(baseURL string, tokens TokenProvider, log *zap.Logger) (*Upstream, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base: %w", err)
	}
	if log == nil {
		log = zap.NewNop()
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
		tokens: tokens,
		log:    log,
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
	token, err := u.tokens.GetAccessToken(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": gin.H{"message": "upstream authentication unavailable", "type": "api_error"},
		})
		return err
	}

	target := u.buildURL(c.Request.URL)
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, c.Request.Body)
	if err != nil {
		return err
	}
	copyHeaders(req.Header, c.Request.Header)
	// Never forward client credentials; inject Grok token.
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Del("Host")
	req.Host = u.base.Host

	resp, err := u.httpClient.Do(req)
	if err != nil {
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
			return rerr
		}
		return u.forward(c, true)
	}
	defer resp.Body.Close()

	filterResponseHeaders(c.Writer.Header(), resp.Header)
	c.Status(resp.StatusCode)

	// Stream body with flushing for SSE.
	flusher, canFlush := c.Writer.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := c.Writer.Write(buf[:n]); werr != nil {
				return werr
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func (u *Upstream) buildURL(reqURL *url.URL) string {
	// Preserve path and query; join with upstream base path if any.
	basePath := strings.TrimRight(u.base.Path, "/")
	path := reqURL.Path
	if basePath != "" && !strings.HasPrefix(path, basePath) {
		// base is like https://api.x.ai/v1 and path is /v1/chat/completions
		// Prefer using full path from client when it already includes /v1.
		// If upstream_base ends with /v1 and path starts with /v1, use host + path.
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
