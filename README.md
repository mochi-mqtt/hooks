[![Go Reference](https://pkg.go.dev/badge/github.com/mochi-co/mqtt.svg)](https://pkg.go.dev/github.com/dgduncan/mochi-cloud-hooks)

# Mochi Hooks

Hooks is a collection of hooks that can be imported and used for Mochi MQTT Broker.
Implementations of certain hooks are inspired by other open source projects

### Table of contents

<!-- MarkdownTOC -->

- [Hooks](#hooks)
    - [Auth](#auth)
        - [HTTP](#http-auth)
    

<!-- /MarkdownTOC -->

### Hooks

#### Auth

##### HTTP

The HTTP hook is a simple HTTP hook that uses two hooks to authorize the client to connect to the broker and authorizes topic level ACLs.
It works by checking the response code of each endpoint. If an endpoint returns back a non `2XX` response a `false` is returned from the hook.

If additional functionality is required, a `callback` can be passed for custom response logic. Configuring a custom `http.Client` and passing one in during configuration is highly recommended as a default `http.Client` will be used.
