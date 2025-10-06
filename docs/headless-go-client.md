# Building a Headless Havoc Client in Go

This guide explains how to replace the Qt-based GUI client with a custom headless client written in Go. It summarises the network protocol used between the existing client and the Havoc teamserver and outlines a reference architecture for interacting with the teamserver programmatically.

## 1. Understand the Transport

* The Qt client connects to the teamserver over a WebSocket endpoint at `wss://<host>:<port>/havoc/` and ignores TLS validation errors. The same URI and TLS behaviour must be reproduced by the headless client. 【F:client/src/Havoc/Connector.cc†L10-L44】
* Messages are sent as binary WebSocket frames that contain JSON payloads. The JSON documents always wrap a `Head` and `Body` object that together form a `Package`. 【F:client/src/Havoc/Connector.cc†L19-L32】【F:client/src/Havoc/Packager.cc†L64-L106】

The Go client can reuse [`gorilla/websocket`](https://github.com/gorilla/websocket) for the transport layer. Use `tls.Config{InsecureSkipVerify: true}` if you need to replicate the GUI client’s decision to ignore certificate issues.

## 2. Reuse the Packager Types

The teamserver already defines Go structs for packages and the enumerations for all message types and sub-events. Instead of hard-coding constants, import or vendor the `teamserver/pkg/packager` module so the headless client can reuse `packager.Head`, `packager.Body`, and the `packager.Type` lookup table. 【F:teamserver/pkg/packager/types.go†L1-L135】

Each outbound and inbound message is modelled as:

```go
type Package struct {
    Head packager.Head `json:"Head"`
    Body packager.Body `json:"Body"`
}
```

The `Head.Event` number selects the high-level channel (listeners, sessions, chat, etc.) and `Body.SubEvent` picks the specific action.

## 3. Authenticate With the Teamserver

The login handshake uses a single package:

1. Set `Head.Event` to `packager.Type.InitConnection.Type`.
2. Set `Body.SubEvent` to `packager.Type.InitConnection.OAuthRequest`.
3. Place the operator username in both `Head.User` and `Body.Info["User"]`.
4. Hash the clear-text password with SHA3-256 and hex-encode it, then store the result in `Body.Info["Password"]`. 【F:client/src/Havoc/Connector.cc†L48-L69】【F:teamserver/cmd/server/teamserver.go†L560-L627】

On success the server replies with `InitConnection.Success` (SubEvent `0x1`), followed by a stream of cached events and profile information so the client can reconstruct state. 【F:teamserver/pkg/events/events.go†L18-L69】

## 4. Consume Server Events

After authentication the teamserver continuously emits events to describe listeners, chat messages, operator presence, agents (“demons”), and build settings. These packages follow the same `Head`/`Body` layout. Key examples include:

* Listener lifecycle notifications (`Event == packager.Type.Listener.Type`). The payload mirrors the handler configuration, so decoding into a generic map suffices. 【F:teamserver/pkg/events/listeners.go†L13-L120】
* Agent session events (`Event == packager.Type.Session.Type`) for new implants, console output, status changes, and task results. 【F:teamserver/pkg/events/demons.go†L17-L86】
* Teamserver logs and profile data (`Event == packager.Type.Teamserver.Type`). 【F:teamserver/pkg/events/teamserver.go†L1-L88】

Store these packages in-memory to maintain headless state (active agents, available listeners, pending tasks) in the same way as the GUI client’s tabs do.

## 5. Send Operator Actions

To task agents or manage listeners the client sends packages back to the server. The dispatcher in the teamserver shows the payloads it expects for each action:

* **Task an agent:**
  * Use `Event == packager.Type.Session.Type` and `SubEvent == packager.Type.Session.Input`.
  * Set `Body.Info["DemonID"]` to the agent’s `NameID` and `Body.Info["CommandID"]` to the numeric command string (e.g. `"1"` for `shell`).
  * Include command-specific arguments in `Body.Info` (for example `"CommandLine"`).
  * Optional: set `Head.OneTime = "true"` for transient jobs such as console-only messages. 【F:teamserver/cmd/server/dispatch.go†L22-L158】

* **Mark an agent:** send `SubEvent == packager.Type.Session.MarkAsDead` with `Body.Info["AgentID"]` and `Body.Info["Marked"]`. 【F:teamserver/pkg/events/demons.go†L88-L110】

* **Add or edit listeners:** reuse the same payloads that the server broadcasts for listener events; the dispatcher will forward them into the handler subsystem. 【F:teamserver/pkg/events/listeners.go†L13-L120】【F:teamserver/cmd/server/dispatch.go†L160-L252】

When broadcasting operator chat messages or status changes, mirror the structures emitted by the GUI client (`Event == packager.Type.Chat.Type`).

## 6. Reference Go Skeleton

The following skeleton shows the control flow for a minimal headless client:

```go
package main

import (
    "crypto/sha3"
    "encoding/hex"
    "log"
    "net/url"
    "time"

    "github.com/gorilla/websocket"

    "Havoc/teamserver/pkg/packager"
)

func main() {
    dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    u := url.URL{Scheme: "wss", Host: "teamserver:40056", Path: "/havoc/"}

    conn, _, err := dialer.Dial(u.String(), nil)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    passHash := sha3.Sum256([]byte("operator-password"))
    login := packager.Package{
        Head: packager.Head{
            Event: packager.Type.InitConnection.Type,
            User:  "operator",
            Time:  time.Now().Format("02/01/2006 15:04:05"),
        },
        Body: packager.Body{
            SubEvent: packager.Type.InitConnection.OAuthRequest,
            Info: map[string]any{
                "User":     "operator",
                "Password": hex.EncodeToString(passHash[:]),
            },
        },
    }

    if err := conn.WriteJSON(login); err != nil {
        log.Fatal(err)
    }

    for {
        var pk packager.Package
        if err := conn.ReadJSON(&pk); err != nil {
            log.Fatal(err)
        }

        // TODO: dispatch on pk.Head.Event / pk.Body.SubEvent
    }
}
```

Replace the `TODO` block with handlers that update your headless state machine and trigger actions. For outgoing messages, fill `packager.Package` values and call `conn.WriteJSON` or `conn.WriteMessage(websocket.BinaryMessage, ...)` as required.

## 7. Optional Enhancements

* Persist the current state to disk so reconnects can replay pending jobs before the server’s cached events arrive.
* Provide a CLI, REST, or gRPC layer on top of the core event loop so that other automation can drive Havoc without the GUI.
* Integrate operator authentication (e.g., environment variables or Vault) instead of storing hashed passwords on disk.

By mirroring the message flow captured above you can fully control the Havoc teamserver from Go without launching the Qt interface.
