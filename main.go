package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	crypto "github.com/Brickchain/go-crypto.v2"
	logger "github.com/Brickchain/go-logger.v1"
	"github.com/Brickchain/go-proxy.v1/pkg/client"
	"github.com/Brickchain/hass-proxy/pkg/controller"
	"github.com/joho/godotenv"
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

func (h *httpClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// just return an OK on the /_ping endpoint
	if r.URL.Path == "/_ping" {
		w.WriteHeader(http.StatusOK)
		return
	}

	logger.Debugf("Request for %s%s", r.Host, r.URL.Path)

	// check that the request is authorized to talk to us
	if !h.controller.Verify(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// create the http request that we should send to the HomeAssistant api
	req, err := http.NewRequest(r.Method, fmt.Sprintf("%s%s", viper.GetString("local"), r.URL.Path), r.Body)
	if err != nil {
		logger.Error(err)
		return
	}

	// copy headers
	for k, v := range r.Header {
		req.Header.Set(k, v[0])
	}
	req.Header.Del("Authorization")

	// set the local hostname
	req.Header.Set("Host", viper.GetString("local_host"))

	// set the X-HASSIO-KEY header based on the HASSIO_TOKEN environment variable
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
		return
	}

	// write response code to the proxy response
	w.WriteHeader(res.StatusCode)

	// copy response headers to the proxy response
	for k, v := range res.Header {
		w.Header().Set(k, v[0])
	}

	// read the response body
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logger.Error(err)
		return
	}

	// write body to the proxy response
	w.Write(body)

}
