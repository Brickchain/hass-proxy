package controller

import jose "gopkg.in/square/go-jose.v1"

// TunnelRegistrationRequest is the message we send to the Brickchain HASS Controller in order to tell it about our existence
type TunnelRegistrationRequest struct {
	Version string `json:"version"`
	Binding string `json:"binding"`
	Secret  string `json:"secret"`
	URL     string `json:"url"`
}

// TunnelRegistrationResponse is the response we get from the Brickchain HASS Controller that contains the public key of the realm
// that we should trust and which mandate roles are allowed to talk to us
type TunnelRegistrationResponse struct {
	RealmKey *jose.JsonWebKey `json:"realmKey"`
	Roles    []string         `json:"roles"`
}
