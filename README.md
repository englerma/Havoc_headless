<div align="center">
  <img width="125px" src="assets/Havoc.png" />
  <h1>Havoc</h1>
  <br/>

  <p><i>Havoc is a modern and malleable post-exploitation command and control framework, created by <a href="https://twitter.com/C5pider">@C5pider</a>.</i></p>
  <br />

  <img src="assets/Screenshots/FullSessionGraph.jpeg" width="90%" /><br />
  <img src="assets/Screenshots/MultiUserAgentControl.png" width="90%" /><br />
  
</div>

### Quick Start

> Please see the [Wiki](https://github.com/HavocFramework/Havoc/wiki) for complete documentation.

Havoc works well on Debian 10/11, Ubuntu 20.04/22.04 and Kali Linux. It's recommended to use the latest versions possible to avoid issues. You'll need a modern version of Qt and Python 3.10.x to avoid build issues.

See the [Installation](https://havocframework.com/docs/installation) docs for instructions. If you run into issues, check the [Known Issues](https://github.com/HavocFramework/Havoc/wiki#known-issues) page as well as the open/closed [Issues](https://github.com/HavocFramework/Havoc/issues) list.

#### Headless Go Client

Havoc ships with a Go-based headless client for operators who prefer a terminal workflow over the Qt GUI. Build the teamserver binary and authenticate with the new `headless` subcommand:

```bash
cd teamserver
go build -o havoc
./havoc headless --host 127.0.0.1 --port 40056 --user operator
```

> **Note:** Run Go commands from the `teamserver` directory. Executing `go build` from the repository root will produce the `go: cannot find main module` error because the module definition lives under `teamserver/`.

Provide the operator password with `--password <value>` or set `HAVOC_PASSWORD` in the environment before launching the command. Use `--no-prompt` when you only want to stream log messages without the interactive shell.

Inside the prompt, type `help` to see every available command. Typical examples are:

* `listeners` – show the listeners the teamserver currently exposes.
* `agents` – list active implants and their status.
* `chat <message>` – broadcast a message to all connected operators.
* `task <agent-id> 12 FromProcessManager=false` – queue the built-in process list command (command identifiers are defined in [`teamserver/pkg/agent/commands.go`](teamserver/pkg/agent/commands.go)).
* `mark <agent-id> Dead` – flag an agent session without closing the connection.

Consult [`docs/headless-go-client.md`](docs/headless-go-client.md) for a deeper dive into extending or automating the headless client.

---

### Features

#### Client

> Cross-platform UI written in C++ and Qt

- Modern, dark theme based on [Dracula](https://draculatheme.com/)


#### Teamserver

> Written in Golang

- Multiplayer
- Payload generation (exe/shellcode/dll)
- HTTP/HTTPS listeners
- Customizable C2 profiles 
- External C2

#### Demon

> Havoc's flagship agent written in C and ASM

- Sleep Obfuscation via [Ekko](https://github.com/Cracked5pider/Ekko), Ziliean or [FOLIAGE](https://github.com/SecIdiot/FOLIAGE)
- x64 return address spoofing
- Indirect Syscalls for Nt* APIs
- SMB support
- Token vault
- Variety of built-in post-exploitation commands
- Patching Amsi/Etw via Hardware breakpoints
- Proxy library loading
- Stack duplication during sleep. 

<div align="center">
  <img src="assets/Screenshots/SessionConsoleHelp.png" width="90%" /><br />
</div>

#### Extensibility

- [External C2](https://github.com/HavocFramework/Havoc/wiki#external-c2)
- Custom Agent Support
  - [Talon](https://github.com/HavocFramework/Talon)
- [Python API](https://github.com/HavocFramework/havoc-py)
- [Modules](https://github.com/HavocFramework/Modules)

---

### Community

You can join the official [Havoc Discord](https://discord.gg/z3PF3NRDE5) to chat with the community! 

### Note

Please do not open any issues regarding detection. 

The Havoc Framework hasn't been developed to be evasive. Rather it has been designed to be as malleable & modular as possible. Giving the operator the capability to add custom features or modules that evades their targets detection system. 
