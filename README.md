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

The `remote` variable sets the remote address for the HASS Controller. Default is fine for most use cases, as the controller code is not yet published.

The `proxy_endpoint` variable sets the address for the server side of this HASS Tunneling Proxy, although the proxy operated at proxy.svc.integrity.app is stable.

In order to authenticate with your Home Assistant installation, use either the `secret`, or the `password` to allow the proxy to connect to the controller. If you do not trust the Integrity HASS Controller with your HASS password, use the secret.

To use the tunnel for the Integrity setup, you need to set a secret from the Home Assistant administration interface.

## Binaries

Brickchain provides binaries for this proxy as part of the [hassio-addons](https://github.com/Brickchain/hassio-addons/) repository and the Docker images it produces for the Home Assistant Add-On Store.
