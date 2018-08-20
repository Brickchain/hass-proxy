package controller

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	crypto "github.com/Brickchain/go-crypto.v2"
	document "github.com/Brickchain/go-document.v2"
	httphandler "github.com/Brickchain/go-httphandler.v2"
	logger "github.com/Brickchain/go-logger.v1"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v1"
)

// Controller manages the connection to the Brickchain HASS Controller
type Controller struct {
	version  string
	url      string
	realmKey *jose.JsonWebKey
	roles    []string
}

// NewController returns a new instance of Controller
func NewController(url string, version string) *Controller {
	return &Controller{
		version: version,
		url:     url,
	}
}

// Register registers to the Brickchain HASS Controller which sends back what public key and mandate roles to trust
func (c *Controller) Register(ourURL, binding, secret string) error {
	req := TunnelRegistrationRequest{
		Version: c.version,
		Binding: binding,
		Secret:  secret,
		URL:     ourURL,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "failed to marshal request")
	}

	res, err := http.Post(c.url, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return errors.Wrap(err, "failed to register to controller")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read response body")
	}

	response := TunnelRegistrationResponse{}
	if err := json.Unmarshal(body, &response); err != nil {
		return errors.Wrap(err, "failed to unmarshal response body")
	}

	c.realmKey = response.RealmKey
	c.roles = response.Roles

	return nil
}

// Verify checks if an http request has the Authorization header with a mandate-token that matches the realm and mandate roles
// that the Brickchain HASS Controller told us about
func (c *Controller) Verify(req *http.Request) (bool, *time.Time) {
	signer, token, err := parseMandateToken(req)
	if err != nil {
		logger.Error(err)
		return false, nil
	}

	var allowed bool
	var until *time.Time
	for _, mandate := range parseMandates(token) {
		if crypto.Thumbprint(mandate.Signer) == crypto.Thumbprint(c.realmKey) {
			if crypto.Thumbprint(signer) == crypto.Thumbprint(mandate.Mandate.Recipient) {
				for _, role := range c.roles {
					if role == mandate.Mandate.Role {
						allowed = true
						if until == nil || mandate.Mandate.ValidUntil.After(*until) {
							until = mandate.Mandate.ValidUntil
						}
					}
				}
			}
		}
	}

	return allowed, until
}

func parseMandateToken(req *http.Request) (*jose.JsonWebKey, *document.MandateToken, error) {
	tokenString := ""
	a := req.Header.Get("Authorization")
	if a != "" {
		var l = strings.Split(a, " ")

		if len(l) < 2 {
			return nil, nil, errors.New("broken auth header")
		}

		if strings.ToUpper(l[0]) != "MANDATE" {
			return nil, nil, errors.New("unknown auth method")
		}

		tokenString = l[1]
	} else {
		cookie, err := req.Cookie("mandate")
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not get mandate cookie")
		}

		tokenString = cookie.Value
	}

	tokenJWS, err := crypto.UnmarshalSignature([]byte(tokenString))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal JWS")
	}

	if len(tokenJWS.Signatures) < 1 || tokenJWS.Signatures[0].Header.JsonWebKey == nil {
		return nil, nil, errors.New("no jwk in token")
	}

	payload, err := tokenJWS.Verify(tokenJWS.Signatures[0].Header.JsonWebKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to verify token")
	}

	token := &document.MandateToken{}
	err = json.Unmarshal(payload, &token)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal token")
	}

	userKey := tokenJWS.Signatures[0].Header.JsonWebKey

	if token.Timestamp.Add(time.Second * time.Duration(token.TTL)).Before(time.Now().UTC()) {
		return nil, nil, errors.New("Token has expired")
	}

	if token.Certificate != "" {
		certChain, err := crypto.VerifyCertificate(token.Certificate, 100)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to verify certificate chain in mandate")
		}

		userKey = certChain.Issuer
	}

	return userKey, token, nil
}

func parseMandates(token *document.MandateToken) []httphandler.AuthenticatedMandate {
	mandates := make([]httphandler.AuthenticatedMandate, 0)

	for _, mandateString := range token.Mandates {
		mandateJWS, err := crypto.UnmarshalSignature([]byte(mandateString))
		if err != nil {
			logger.Debug(errors.Wrap(err, "failed to unmarshal mandate"))
			continue
		}

		if len(mandateJWS.Signatures) < 1 {
			logger.Debug(errors.New("No signers of mandate"))
			continue
		}

		mandatePayload, err := mandateJWS.Verify(mandateJWS.Signatures[0].Header.JsonWebKey)
		if err != nil {
			logger.Debug(errors.Wrap(err, "failed to verify mandate signature"))
			continue
		}

		var mandate *document.Mandate
		err = json.Unmarshal(mandatePayload, &mandate)
		if err != nil {
			logger.Debug(errors.Wrap(err, "failed to unmarshal mandate"))
			continue
		}

		if mandate.ValidFrom == nil || mandate.Timestamp.After(time.Now().UTC()) {
			logger.Debug(errors.New("Mandate is not yet valid"))
			continue
		}

		if mandate.ValidFrom != nil && mandate.ValidFrom.After(time.Now().UTC()) {
			logger.Debug(errors.New("Mandate is not yet valid"))
			continue
		}

		if mandate.ValidUntil != nil && mandate.ValidUntil.Before(time.Now().UTC()) {
			logger.Debug("Mandate has expired")
			continue
		}

		signingKey := mandateJWS.Signatures[0].Header.JsonWebKey

		if mandate.GetCertificate() != "" {
			chain, err := crypto.VerifyCertificate(mandate.GetCertificate(), 10)
			if err != nil {
				logger.Debug(errors.Wrap(err, "could not verify certificate chain"))
				continue
			}

			signingKey = chain.Issuer
		}

		mandates = append(mandates, httphandler.AuthenticatedMandate{
			Mandate: mandate,
			Signer:  signingKey,
		})
	}

	return mandates
}
