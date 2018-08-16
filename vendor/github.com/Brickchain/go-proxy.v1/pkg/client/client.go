package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	crypto "github.com/Brickchain/go-crypto.v2"
	logger "github.com/Brickchain/go-logger.v1"
	proxy "github.com/Brickchain/go-proxy.v1"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v1"

	document "github.com/Brickchain/go-document.v2"
)

type ProxyClient struct {
	base        string
	id          string
	url         string
	endpoint    string
	proxyDomain string
	conn        *websocket.Conn
	writeLock   *sync.Mutex
	regError    error
	regDone     *sync.WaitGroup
	initialized bool
	connected   bool
	handler     http.Handler
	key         *jose.JsonWebKey
	lastPing    time.Time
	wg          sync.WaitGroup
}

func NewProxyClient(endpoint string) (*ProxyClient, error) {
	p := &ProxyClient{
		endpoint: endpoint,
		// proxyDomain: proxyDomain,
		writeLock: &sync.Mutex{},
		lastPing:  time.Now(),
		regDone:   &sync.WaitGroup{},
		wg:        sync.WaitGroup{},
	}

	p.regDone.Add(1)

	go p.subscribe()

	return p, nil
}

func (p *ProxyClient) connect() error {
	host := strings.Replace(strings.Replace(p.endpoint, "https://", "", 1), "http://", "", 1)
	schema := "ws"
	if strings.HasPrefix(p.endpoint, "https://") {
		schema = "wss"
	}

	u := url.URL{Scheme: schema, Host: host, Path: "/proxy/subscribe"}

	var err error
	p.conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	p.connected = true

	p.lastPing = time.Now()

	return nil
}

func (p *ProxyClient) write(b []byte) error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()

	if p.conn == nil {
		return errors.New("Not connected")
	}

	return p.conn.WriteMessage(websocket.TextMessage, b)
}

func (p *ProxyClient) Register(key *jose.JsonWebKey) (string, error) {

	p.id = crypto.Thumbprint(key)
	p.key = key

	p.regDone.Wait()

	// time.Sleep(time.Second * 3)

	return p.base, nil

}

func (p *ProxyClient) register() error {

	for {
		if p.connected {
			break
		}

		time.Sleep(time.Millisecond * 10)
	}

	mandateToken := document.NewMandateToken([]string{}, p.endpoint, 60)

	b, _ := json.Marshal(mandateToken)

	signer, err := crypto.NewSigner(p.key)
	if err != nil {
		return err
	}

	jws, err := signer.Sign(b)
	if err != nil {
		return err
	}

	jwsCompact, _ := jws.CompactSerialize()

	regReq := proxy.NewRegistrationRequest(jwsCompact)
	regReqBytes, _ := json.Marshal(regReq)

	if err := p.write(regReqBytes); err != nil {
		return err
	}

	p.regDone.Wait()
	if p.regError != nil {
		return p.regError
	}

	// p.base = fmt.Sprintf("%s.%s", p.id, p.proxyDomain)

	return nil
}

func (p *ProxyClient) SetHandler(handler http.Handler) {
	p.handler = handler
}

func (p *ProxyClient) Wait() {
	p.wg.Wait()
}

func (p *ProxyClient) subscribe() error {
	p.wg.Add(1)
	defer p.wg.Done()

	disconnect := func() {
		if p.connected {
			p.conn.Close()
			p.connected = false
		}
	}

	go func() {
		for {
			if !p.connected {
				time.Sleep(time.Second)
				continue
			}

			if p.lastPing.Add(time.Second * 20).Before(time.Now()) {
				logger.Warningf("No ping for %2.f seconds", time.Now().Sub(p.lastPing).Seconds())
				disconnect()
				time.Sleep(time.Second)
			}

			time.Sleep(time.Second)
		}
	}()

	for {
		if !p.connected {
			// logger.Debug("Connecting to proxy...")
			if err := p.connect(); err != nil {
				logger.Error(errors.Wrap(err, "failed to connect to proxy"))
				disconnect()
				time.Sleep(time.Second * 10)
				continue
			}
			// logger.Debug("Connected!")

			if p.key != nil {
				go func() {
					// logger.Debug("Registering to proxy...")
					if err := p.register(); err != nil {
						logger.Error(errors.Wrap(err, "failed to register to proxy"))
						disconnect()
					} else {
						// logger.Debug("Registered!")
					}
				}()
			}
		}

		_, body, err := p.conn.ReadMessage()
		if err != nil {
			logger.Error(errors.Wrap(err, "failed to read message"))
			disconnect()
			continue
		}
		// logger.Infof("recv: %s", body)

		go func() {
			docType, err := document.GetType(body)
			if err != nil {
				logger.Error(errors.Wrap(err, "failed to get document type"))
			}

			switch docType {
			case proxy.SchemaBase + "/ping.json":
				p.lastPing = time.Now()

			case proxy.SchemaBase + "/registration-response.json":
				p.lastPing = time.Now()

				r := &proxy.RegistrationResponse{}
				if err := json.Unmarshal(body, &r); err != nil {
					logger.Error(errors.Wrap(err, "failed to unmarshal registration-response"))
				}

				if r.KeyID != p.id {
					p.regError = errors.New("Wrong KeyID in registration")
				} else {
					if r.Hostname != "" {
						p.base = r.Hostname
					}
					if !p.initialized {
						p.initialized = true
						p.regDone.Done()
					}
				}

			case proxy.SchemaBase + "/http-request.json":
				p.lastPing = time.Now()

				if p.handler == nil {
					logger.Error("No handler set, can't process http-request")
					return
				}

				req := &proxy.HttpRequest{}
				if err := json.Unmarshal(body, &req); err != nil {
					logger.Error(errors.Wrap(err, "failed to unmarshal http-request"))
					return
				}

				if req != nil {
					r := &http.Request{
						Method: req.Method,
						URL: &url.URL{
							Host: p.base,
							Path: req.URL,
						},
						RequestURI: req.URL,
						Header:     make(http.Header),
						Host:       p.base,
					}

					if req.Headers["X-Forwarded-Host"] != "" {
						r.Host = req.Headers["X-Forwarded-Host"]
					}

					for k, v := range req.Headers {
						r.Header.Set(k, v)
					}

					if req.Body != "" {
						body, err := base64.StdEncoding.DecodeString(req.Body)
						if err == nil {
							r.Body = nopCloser{bytes.NewBuffer(body)}
						} else {
							logger.Error("Failed to decode body")
						}
					}

					w := httptest.NewRecorder()

					p.handler.ServeHTTP(w, r)

					res := proxy.NewHttpResponse(req.ID, w.Result().StatusCode)
					res.ContentType = w.Result().Header.Get("Content-Type")

					body, _ := ioutil.ReadAll(w.Result().Body)
					res.Body = base64.StdEncoding.EncodeToString(body)

					res.Headers = make(map[string]string)
					for k, v := range w.Result().Header {
						res.Headers[k] = v[0]
					}

					b, _ := json.Marshal(res)

					// logger.Debugf("Sending response: %s", b)
					if err := p.write(b); err != nil {
						logger.Error(errors.Wrap(err, "failed to send http-response"))
						disconnect()
						return
					}
				}
			}
		}()
	}
}

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error {
	return nil
}
