HASS Tunneling Proxy
====================

The HASS tunneling proxy is the VPN component for the Brickchain HASS service, to allow external access to Home Assistant through the Home Assistant access layer on the Integrity platform.

The tunneling proxy uses the client library in [go-proxy.v1](https://github.com/Brickchain/go-proxy.v1).

The configuration is done through a set of environment variables, as taken from `main.go`:

```golang
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
```

To use the tunnel for the Integrity setup, you need to set a secret from the Home Assistant administration interface.

## Binaries

Brickchain provides binaries for this proxy as part of the [hassio-addons](https://github.com/Brickchain/hassio-addons/) repository and the Docker images it produces for the Home Assistant Add-On Store.
