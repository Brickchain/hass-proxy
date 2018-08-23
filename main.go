package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	crypto "github.com/Brickchain/go-crypto.v2"
	logger "github.com/Brickchain/go-logger.v1"
	"github.com/Brickchain/go-proxy.v1/pkg/client"
	"github.com/Brickchain/hass-proxy/pkg/controller"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v1"
)

// Version holds the version we're currently running
var Version = "dev"

func main() {
	_ = godotenv.Load(".env")
	viper.AutomaticEnv()
	viper.SetDefault("log_formatter", "text")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("secret", "")
	viper.SetDefault("remote", "https://hass.svc.integrity.app/service/hass/tunnel")
	viper.SetDefault("proxy_endpoint", "https://proxy.svc.integrity.app")
	viper.SetDefault("local", "http://hassio/homeassistant")
	viper.SetDefault("local_host", "hassio")
	viper.SetDefault("password", "")
	viper.SetDefault("key", "hass-proxy.pem")
	viper.SetDefault("hassio_token", "")

	logger.SetLevel(viper.GetString("log_level"))
	logger.SetFormatter(viper.GetString("log_formatter"))

	logger.Infof("Starting Brickchain HASS Proxy version %s", Version)

	if viper.GetString("secret") == "" {
		logger.Fatalf("You need to set a secret!")
	}

	// split out the binding and secret parts of the secret environment variable
	parts := strings.Split(viper.GetString("secret"), ".")
	binding := parts[0]
	secret := parts[1]

	controller := controller.NewController(viper.GetString("remote"), Version)

	var key *jose.JsonWebKey

	// check if there is already a key file present on the filesystem and load it, otherwise create one
	_, err := os.Stat(viper.GetString("key"))
	if err != nil {
		key, err = crypto.NewKey()
		if err != nil {
			logger.Fatal(err)
		}

		kb, err := crypto.MarshalToPEM(key)
		if err != nil {
			logger.Fatal(err)
		}

		if err := ioutil.WriteFile(viper.GetString("key"), kb, 0600); err != nil {
			logger.Fatal(err)
		}
	} else {
		kb, err := ioutil.ReadFile(viper.GetString("key"))
		if err != nil {
			logger.Fatal(err)
		}

		key, err = crypto.UnmarshalPEM(kb)
		if err != nil {
			logger.Fatal(err)
		}
	}

	// connect to the proxy
	p, err := client.NewProxyClient(viper.GetString("proxy_endpoint"))
	if err != nil {
		logger.Fatal(err)
	} else {
		hostname, err := p.Register(key)
		if err != nil {
			logger.Fatal(err)
		}

		logger.Infof("Got hostname: %s", hostname)

		p.SetHandler(&httpClient{controller})

		// register to the Brickchain HASS Controller
		if err := controller.Register(fmt.Sprintf("https://%s", hostname), binding, secret); err != nil {
			logger.Fatal(err)
		}
	}

	p.Wait()
}

type httpClient struct {
	controller *controller.Controller
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *httpClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// just return an OK on the /_ping endpoint
	if r.URL.Path == "/_ping" {
		w.WriteHeader(http.StatusOK)
		return
	}

	logger.Debugf("Request for %s%s", r.Host, r.URL.Path)

	// check that the request is authorized to talk to us
	allowed, until := h.controller.Verify(r)
	if !allowed || time.Now().UTC().After(*until) {
		logger.Debug("Unauthorized")
		w.Write([]byte("Unauthorized"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// This is a websocket upgrade request, so let's setup a websocket client towards that same path on HomeAssistant and proxy the messages
	if strings.ToLower(r.Header.Get("Connection")) == "upgrade" && strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {

		respHeaders := make(http.Header)
		respHeaders.Add("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		conn, err := upgrader.Upgrade(w, r, respHeaders)
		if err != nil {
			http.Error(w, errors.Wrap(err, "failed to upgrade to websocket").Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Build local address
		host := strings.Replace(strings.Replace(viper.GetString("local"), "https://", "", 1), "http://", "", 1)
		schema := "ws"
		if strings.HasPrefix(viper.GetString("local"), "https://") {
			schema = "wss"
		}
		u := url.URL{Scheme: schema, Host: host, Path: r.URL.Path}

		// Remove headers that we should not forward
		headers := http.Header{}
		for k, v := range r.Header {
			switch strings.ToUpper(k) {
			case "CONNECTION":
			case "UPGRADE":
			case "SEC-WEBSOCKET-KEY":
			case "SEC-WEBSOCKET-VERSION":
			case "SEC-WEBSOCKET-EXTENSIONS":
			default:
				headers.Set(k, v[0])
			}
		}

		// Dial the local websocket
		clientConn, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
		if err != nil {
			logger.Error(err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer clientConn.Close()

		// Read upstream messages and write to local websocket
		done := make(chan struct{})
		defer close(done)
		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(until.Sub(time.Now().UTC())): // Close socket when mandate token expires
					logger.Debugf("Mandate token expired, closing connection")
					conn.Close()
					clientConn.Close()
					return
				default:
					typ, body, err := conn.ReadMessage()
					if err != nil {
						logger.Error(err)
						return
					}

					if err := clientConn.WriteMessage(typ, body); err != nil {
						logger.Error(err)
						return
					}
				}
				time.Sleep(time.Millisecond * 10)
			}
		}()

		// Read messages from local websocket and forward to upstream
		for {
			typ, body, err := clientConn.ReadMessage()
			if err != nil {
				logger.Error(err)
				return
			}

			m := haMessage{}
			if err := json.Unmarshal(body, &m); err != nil {
				logger.Error(err)
				return
			}

			switch m.Type {
			case "auth_required":
				// Since this websocket connection is validated with a MandateToken we can trust it and can intercept the auth_required message and do the login.
				// This way the user don't need the password for HomeAssistant as long as they have a valid Mandate.
				doAuth := haMessage{
					Type:        "auth",
					APIPassword: viper.GetString("hassio_token"),
				}
				b, _ := json.Marshal(doAuth)
				if err := clientConn.WriteMessage(websocket.TextMessage, b); err != nil {
					logger.Error(err)
					return
				}

				m.Type = "auth_ok"
				b, _ = json.Marshal(m)
				if err := conn.WriteMessage(typ, b); err != nil {
					logger.Error(err)
					return
				}
			default:
				if err := conn.WriteMessage(typ, body); err != nil {
					logger.Error(err)
					return
				}
			}
			time.Sleep(time.Millisecond * 10)
		}
	} else {

		// create the http request that we should send to the HomeAssistant api
		req, err := http.NewRequest(r.Method, fmt.Sprintf("%s%s", viper.GetString("local"), r.URL.Path), r.Body)
		if err != nil {
			logger.Error(err)
			w.Write([]byte(err.Error()))
			return
		}

		// copy headers
		for k, v := range r.Header {
			req.Header.Set(k, v[0])
		}

		// set the local hostname
		req.Header.Set("Host", viper.GetString("local_host"))

		// set the X-HA-ACCESS header based on the HASSIO_TOKEN environment variable
		if viper.GetString("hassio_token") != "" {
			req.Header.Set("X-HA-ACCESS", viper.GetString("hassio_token"))
		}

		client := &http.Client{
			Timeout: time.Second * 15,
		}

		// execute the request
		res, err := client.Do(req)
		if err != nil {
			logger.Error(err)
			if res != nil {
				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					logger.Error(err)
					return
				}
				w.Write(body)
				w.WriteHeader(res.StatusCode)
			} else {
				w.Write([]byte(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		logger.Debugf("Request finished with status: %s", res.Status)

		// copy response headers to the proxy response
		for k, v := range res.Header {
			w.Header().Set(k, v[0])
		}

		// read the response body
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			logger.Error(err)
			w.Write([]byte(err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// write body to the proxy response
		w.Write(body)

		// write response code to the proxy response
		w.WriteHeader(res.StatusCode)
	}
}

// Basic type of messages going over the HomeAssistant websocket API
type haMessage struct {
	Type        string `json:"type"`
	HAVersion   string `json:"ha_version,omitempty"`
	APIPassword string `json:"api_password,omitempty"`
}
