package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mochi-co/mqtt/v2"
	"github.com/mochi-co/mqtt/v2/packets"
)

// TODO : What is timeout for? I think it may be to prevent too many requests. This seems like the incorrect place for this
type HTTPAuthHook struct {
	httpclient     *http.Client
	aclhost        *url.URL
	clientauthhost *url.URL
	superuserhost  *url.URL // currently unused
	mqtt.HookBase
}

type HTTPAuthHookConfig struct {
	ACLHost                  *url.URL
	SuperUserHost            *url.URL
	ClientAuthenticationHost *url.URL // currently unused
	RoundTripper             http.RoundTripper
}

type SuperuserCheckPOST struct {
	Username string `json:"username"`
}

type ClientCheckPOST struct {
	ClientID string `json:"clientid"`
	Password string `json:"password"`
	Username string `json:"username"`
}

type ACLCheckPOST struct {
	Username string `json:"username"`
	ClientID string `json:"clientid"`
	Topic    string `json:"topic"`
	ACC      string `json:"acc"`
}

type TimeoutConfig struct {
	TimeoutDuration time.Duration
}

type CacheConfig struct {
	Duration time.Duration
}

func (h *HTTPAuthHook) ID() string {
	return "http-auth-hook"
}

func (h *HTTPAuthHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnACLCheck,
		mqtt.OnConnectAuthenticate,
	}, []byte{b})
}

func (h *HTTPAuthHook) Init(config any) error {
	if config == nil {
		return errors.New("nil config")
	}

	authHookConfig, ok := config.(HTTPAuthHookConfig)
	if !ok {
		return errors.New("improper config")
	}

	if !validateConfig(authHookConfig) {
		return errors.New("hostname configs failed validation")
	}

	h.httpclient = NewTransport(authHookConfig.RoundTripper)

	h.aclhost = authHookConfig.ACLHost
	h.clientauthhost = authHookConfig.ClientAuthenticationHost
	h.superuserhost = authHookConfig.SuperUserHost
	return nil
}

func (h *HTTPAuthHook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {

	payload := ClientCheckPOST{
		ClientID: cl.ID,
		Password: string(pk.Connect.Password),
		Username: string(pk.Connect.Username),
	}

	resp, err := h.makeRequest(http.MethodPost, h.clientauthhost, payload)
	if err != nil {
		h.Log.Error().Err(err)
		return false
	}

	// Block on proper 4xx response
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false
	}

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (h *HTTPAuthHook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {

	payload := ACLCheckPOST{
		ClientID: cl.ID,
		Username: string(cl.Properties.Username),
		Topic:    topic,
		ACC:      strconv.FormatBool(write),
	}

	resp, err := h.makeRequest(http.MethodPost, h.aclhost, payload)
	if err != nil {
		h.Log.Error().Err(err)
		return false
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false
	}

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (h *HTTPAuthHook) makeRequest(requestType string, url *url.URL, payload any) (*http.Response, error) {
	var buffer io.Reader
	if payload == nil {
		buffer = http.NoBody
	} else {
		rb, err := json.Marshal(payload)
		if err != nil {
			h.Log.Err(err).Msg("")
			return nil, err
		}
		buffer = bytes.NewBuffer(rb)
	}

	req, err := http.NewRequest(requestType, url.String(), buffer)
	if err != nil {
		h.Log.Error().Err(err)
		return nil, err
	}

	resp, err := h.httpclient.Do(req)
	if err != nil {
		h.Log.Error().Err(err)
		return nil, err
	}

	return resp, nil
}

func validateConfig(config HTTPAuthHookConfig) bool {
	if (config.ACLHost == nil) || (config.ClientAuthenticationHost == nil) {
		return false
	}
	return true

	// return !((config.ACLHost == nil) || (config.ClientAuthenticationHost == nil))
}

// ***************************************

// Transport represents everything required for adding to the roundtripper interface
type Transport struct {
	OriginalTransport http.RoundTripper
}

// NewTransport creates a new Transport object with any passed in information
func NewTransport(rt http.RoundTripper) *http.Client {
	if rt == nil {
		rt = &Transport{
			OriginalTransport: http.DefaultTransport,
		}
	}

	return &http.Client{
		Transport: rt,
	}
}

// RoundTrip goes through the HTTP RoundTrip implementation and attempts to add ASAP if not passed it
func (st *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return st.OriginalTransport.RoundTrip(r)
}
