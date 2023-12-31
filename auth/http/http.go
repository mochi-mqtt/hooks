package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
)

// Hook is a hook that makes http requests to an external service
type Hook struct {
	httpClient     *http.Client
	aclhost        *url.URL
	clientauthhost *url.URL
	superuserhost  *url.URL // currently unused
	callback       func(resp *http.Response) bool
	mqtt.HookBase
}

// Options is a struct that contains all the information required to configure the http hook
// It is the responsibility of the configurer to pass a properly configured RoundTripper that takes
// care other requirements such as authentication, timeouts, retries, etc
type Options struct {
	ACLHost                  *url.URL
	SuperUserHost            *url.URL
	ClientAuthenticationHost *url.URL // currently unused
	RoundTripper             http.RoundTripper
	Callback                 func(resp *http.Response) bool
}

// ClientCheckPOST is the struct that is sent to the client authentication endpoint
type ClientCheckPOST struct {
	ClientID string `json:"clientid"`
	Password string `json:"password"`
	Username string `json:"username"`
}

// ACLCheckPOST is the struct that is sent to the acl endpoint
type ACLCheckPOST struct {
	Username string `json:"username"`
	ClientID string `json:"clientid"`
	Topic    string `json:"topic"`
	ACC      string `json:"acc"`
}

// ID returns the ID of the hook
func (h *Hook) ID() string {
	return "http-auth-hook"
}

// Provides returns whether or not the hook provides the given hook
func (h *Hook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mqtt.OnACLCheck,
		mqtt.OnConnectAuthenticate,
	}, []byte{b})
}

// Init initializes the hook with the given config
func (h *Hook) Init(config any) error {
	if config == nil {
		return errors.New("nil config")
	}

	authHookConfig, ok := config.(Options)
	if !ok {
		return errors.New("improper config")
	}

	if !validateConfig(authHookConfig) {
		return errors.New("hostname configs failed validation")
	}

	h.callback = defaultCallback
	if authHookConfig.Callback != nil {
		h.Log.Debug("replacing default callback with one included in options")
		h.callback = authHookConfig.Callback
	}

	h.httpClient = NewTransport(authHookConfig.RoundTripper)

	h.aclhost = authHookConfig.ACLHost
	h.clientauthhost = authHookConfig.ClientAuthenticationHost
	h.superuserhost = authHookConfig.SuperUserHost
	return nil
}

// OnConnectAuthenticate is called when a client attempts to connect to the server
func (h *Hook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {

	payload := ClientCheckPOST{
		ClientID: cl.ID,
		Password: string(pk.Connect.Password),
		Username: string(pk.Connect.Username),
	}

	resp, err := h.makeRequest(http.MethodPost, h.clientauthhost, payload)
	if err != nil {
		h.Log.Error("error occurred while making http request", "error", err)
		return false
	}

	return h.callback(resp)
}

// OnACLCheck is called when a client attempts to publish or subscribe to a topic
func (h *Hook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {

	payload := ACLCheckPOST{
		ClientID: cl.ID,
		Username: string(cl.Properties.Username),
		Topic:    topic,
		ACC:      strconv.FormatBool(write),
	}

	resp, err := h.makeRequest(http.MethodPost, h.aclhost, payload)
	if err != nil {
		h.Log.Error("error occurred while making http request", "error", err)
		return false
	}

	return h.callback(resp)
}

func (h *Hook) makeRequest(requestType string, url *url.URL, payload any) (*http.Response, error) {
	var buffer io.Reader
	if payload == nil {
		buffer = http.NoBody
	} else {
		rb, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		buffer = bytes.NewBuffer(rb)
	}

	req, err := http.NewRequest(requestType, url.String(), buffer)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func validateConfig(config Options) bool {
	if (config.ACLHost == nil) || (config.ClientAuthenticationHost == nil) {
		return false
	}
	return true
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

func defaultCallback(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
