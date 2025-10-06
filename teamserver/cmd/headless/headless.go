package headless

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"

	"Havoc/pkg/packager"
)

var (
	headlessFlags struct {
		Host           string
		Port           int
		User           string
		Password       string
		InsecureTLS    bool
		NonInteractive bool
	}
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var CobraHeadless = &cobra.Command{
	Use:   "headless",
	Short: "Run the headless Havoc client",
	RunE: func(cmd *cobra.Command, args []string) error {
		if headlessFlags.User == "" {
			return errors.New("--user is required")
		}

		password := headlessFlags.Password
		if password == "" {
			password = os.Getenv("HAVOC_PASSWORD")
		}
		if password == "" {
			return errors.New("--password flag or HAVOC_PASSWORD env var must be set")
		}

		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		client, err := newHeadlessClient(headlessFlags.Host, headlessFlags.Port, headlessFlags.User, password, headlessFlags.InsecureTLS)
		if err != nil {
			return err
		}
		defer client.Close()

		go client.runReader(ctx)

		select {
		case <-client.ready:
		case <-client.done:
			if client.readErr != nil {
				return client.readErr
			}
			return errors.New("connection closed before authentication completed")
		case <-ctx.Done():
			return ctx.Err()
		}

		if !headlessFlags.NonInteractive {
			if err := client.interactive(ctx, cancel); err != nil {
				cancel()
				if !errors.Is(err, context.Canceled) {
					return err
				}
			}
		} else {
			<-ctx.Done()
		}

		cancel()
		<-client.done
		return client.readErr
	},
}

func init() {
	CobraHeadless.Flags().StringVar(&headlessFlags.Host, "host", "127.0.0.1", "teamserver host")
	CobraHeadless.Flags().IntVar(&headlessFlags.Port, "port", 40056, "teamserver port")
	CobraHeadless.Flags().StringVar(&headlessFlags.User, "user", "", "operator username")
	CobraHeadless.Flags().StringVar(&headlessFlags.Password, "password", "", "operator password (falls back to HAVOC_PASSWORD env var)")
	CobraHeadless.Flags().BoolVar(&headlessFlags.InsecureTLS, "insecure", true, "skip TLS certificate verification")
	CobraHeadless.Flags().BoolVar(&headlessFlags.NonInteractive, "no-prompt", false, "run without the interactive prompt (logs only)")
}

type headlessClient struct {
	conn     *websocket.Conn
	username string
	state    *clientState

	ready chan struct{}
	done  chan struct{}
	once  sync.Once
	logMu sync.Mutex

	readErr error
}

type clientState struct {
	mu        sync.RWMutex
	listeners map[string]listenerSummary
	agents    map[string]*agentSummary
	chat      []chatMessage
	profile   string
}

type listenerSummary struct {
	Name      string
	Protocol  string
	HostBind  string
	PortBind  string
	Hosts     string
	Status    string
	UpdatedAt time.Time
}

type agentSummary struct {
	ID         string
	Hostname   string
	Username   string
	InternalIP string
	ExternalIP string
	Process    string
	PID        string
	Arch       string
	Sleep      string
	LastSeen   string
	FirstSeen  string
	Active     bool
	Mark       string
}

type chatMessage struct {
	Time    string
	User    string
	Message string
}

func newHeadlessClient(host string, port int, user, password string, insecure bool) (*headlessClient, error) {
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}
	u := url.URL{Scheme: "wss", Host: fmt.Sprintf("%s:%d", host, port), Path: "/havoc/"}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &headlessClient{
		conn:     conn,
		username: user,
		state: &clientState{
			listeners: make(map[string]listenerSummary),
			agents:    make(map[string]*agentSummary),
		},
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}

	if err := client.authenticate(password); err != nil {
		_ = conn.Close()
		return nil, err
	}

	client.printf("connected to %s", u.String())
	return client, nil
}

func (c *headlessClient) authenticate(password string) error {
	hash := sha3.Sum256([]byte(password))
	pkg := packager.Package{
		Head: packager.Head{
			Event: packager.Type.InitConnection.Type,
			User:  c.username,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},
		Body: packager.Body{
			SubEvent: packager.Type.InitConnection.OAuthRequest,
			Info: map[string]any{
				"User":     c.username,
				"Password": hex.EncodeToString(hash[:]),
			},
		},
	}
	return c.sendPackage(pkg)
}

func (c *headlessClient) sendPackage(pk packager.Package) error {
	data, err := json.Marshal(pk)
	if err != nil {
		return err
	}
	c.logMu.Lock()
	defer c.logMu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *headlessClient) runReader(ctx context.Context) {
	defer close(c.done)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.readErr = err
			c.printf("connection closed: %v", err)
			return
		}

		var pk packager.Package
		if err := json.Unmarshal(data, &pk); err != nil {
			c.printf("failed to decode package: %v", err)
			continue
		}

		c.handlePackage(pk)
	}
}

func (c *headlessClient) handlePackage(pk packager.Package) {
	switch pk.Head.Event {
	case packager.Type.InitConnection.Type:
		c.handleInitConnection(pk)
	case packager.Type.Listener.Type:
		c.handleListener(pk)
	case packager.Type.Session.Type:
		c.handleSession(pk)
	case packager.Type.Teamserver.Type:
		c.handleTeamserver(pk)
	case packager.Type.Chat.Type:
		c.handleChat(pk)
	default:
		c.printf("received event %d/%d", pk.Head.Event, pk.Body.SubEvent)
	}
}

func (c *headlessClient) handleInitConnection(pk packager.Package) {
	switch pk.Body.SubEvent {
	case packager.Type.InitConnection.Success:
		c.once.Do(func() { close(c.ready) })
		c.printf("authenticated as %s", c.username)
	case packager.Type.InitConnection.Error:
		c.readErr = errors.New(stringValue(pk.Body.Info, "Message"))
		c.printf("authentication failed: %s", c.readErr)
		_ = c.conn.Close()
	case packager.Type.InitConnection.Profile:
		profile := stringValue(pk.Body.Info, "Demon")
		c.state.mu.Lock()
		c.state.profile = profile
		c.state.mu.Unlock()
		c.printf("received profile information (%d bytes)", len(profile))
	}
}

func (c *headlessClient) handleListener(pk packager.Package) {
	info := mapToStringMap(pk.Body.Info)
	name := info["Name"]
	if name == "" {
		name = info["ListenerName"]
	}

	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	summary := c.state.listeners[name]
	summary.Name = name
	if v, ok := info["Protocol"]; ok {
		summary.Protocol = v
	}
	if v, ok := info["HostBind"]; ok {
		summary.HostBind = v
	}
	if v, ok := info["PortBind"]; ok {
		summary.PortBind = v
	}
	if v, ok := info["Hosts"]; ok {
		summary.Hosts = v
	}
	if v, ok := info["Status"]; ok {
		summary.Status = v
	}
	summary.UpdatedAt = time.Now()

	switch pk.Body.SubEvent {
	case packager.Type.Listener.Add, packager.Type.Listener.Edit, packager.Type.Listener.Mark:
		c.state.listeners[name] = summary
		c.printf("listener %s (%s) -> %s", summary.Name, summary.Protocol, summary.Status)
	case packager.Type.Listener.Remove:
		delete(c.state.listeners, name)
		c.printf("listener %s removed", name)
	case packager.Type.Listener.Error:
		c.printf("listener error [%s]: %s", name, info["Error"])
	}
}

func (c *headlessClient) handleSession(pk packager.Package) {
	info := pk.Body.Info
	switch pk.Body.SubEvent {
	case packager.Type.Session.NewSession:
		id := stringValue(info, "NameID")
		if id == "" {
			return
		}
		agent := &agentSummary{
			ID:         id,
			Hostname:   stringValue(info, "Hostname"),
			Username:   stringValue(info, "Username"),
			InternalIP: stringValue(info, "InternalIP"),
			ExternalIP: stringValue(info, "ExternalIP"),
			Process:    stringValue(info, "ProcessName"),
			PID:        stringValue(info, "ProcessPID"),
			Arch:       stringValue(info, "ProcessArch"),
			Sleep:      stringValue(info, "SleepDelay"),
			FirstSeen:  stringValue(info, "FirstCallIn"),
			LastSeen:   stringValue(info, "LastCallIn"),
			Mark:       stringValue(info, "Active"),
		}
		agent.Active = strings.EqualFold(stringValue(info, "Active"), "true")
		c.state.mu.Lock()
		c.state.agents[id] = agent
		c.state.mu.Unlock()
		c.printf("agent %s registered from %s (%s)", agent.ID, agent.Hostname, agent.InternalIP)
	case packager.Type.Session.Output:
		agentID := stringValue(info, "DemonID")
		output := stringValue(info, "Output")
		if decoded, err := base64.StdEncoding.DecodeString(output); err == nil && len(decoded) > 0 {
			output = string(decoded)
		}
		c.printf("agent %s output:\n%s", agentID, output)
	case packager.Type.Session.MarkAsDead:
		id := stringValue(info, "AgentID")
		mark := stringValue(info, "Marked")
		c.state.mu.Lock()
		if agent, ok := c.state.agents[id]; ok {
			agent.Mark = mark
			agent.Active = strings.EqualFold(mark, "Alive")
		}
		c.state.mu.Unlock()
		c.printf("agent %s marked as %s", id, mark)
	case packager.Type.Session.Remove:
		id := stringValue(info, "AgentID")
		c.state.mu.Lock()
		delete(c.state.agents, id)
		c.state.mu.Unlock()
		c.printf("agent %s removed", id)
	}
}

func (c *headlessClient) handleTeamserver(pk packager.Package) {
	if text := stringValue(pk.Body.Info, "Text"); text != "" {
		c.printf("teamserver: %s", text)
		return
	}
	if profile := stringValue(pk.Body.Info, "profile"); profile != "" {
		c.printf("teamserver profile: %s", profile)
	}
}

func (c *headlessClient) handleChat(pk packager.Package) {
	switch pk.Body.SubEvent {
	case packager.Type.Chat.NewMessage:
		for user, raw := range pk.Body.Info {
			rawStr := fmt.Sprintf("%v", raw)
			decoded := rawStr
			if b, err := base64.StdEncoding.DecodeString(rawStr); err == nil {
				decoded = string(b)
			}
			c.state.mu.Lock()
			c.state.chat = append(c.state.chat, chatMessage{Time: pk.Head.Time, User: user, Message: decoded})
			c.state.mu.Unlock()
			c.printf("chat [%s] %s: %s", pk.Head.Time, user, decoded)
		}
	case packager.Type.Chat.NewUser:
		c.printf("chat: user %s connected", stringValue(pk.Body.Info, "User"))
	case packager.Type.Chat.UserDisconnected:
		c.printf("chat: user %s disconnected", stringValue(pk.Body.Info, "User"))
	case packager.Type.Chat.NewSession:
		c.printf("chat: new session %s", stringValue(pk.Body.Info, "Session"))
	}
}

func (c *headlessClient) interactive(ctx context.Context, cancel context.CancelFunc) error {
	fmt.Println("Headless Havoc client ready. Type 'help' for a list of commands.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return context.Canceled
		default:
		}

		fields := strings.Fields(line)
		cmd := strings.ToLower(fields[0])
		args := fields[1:]

		switch cmd {
		case "help":
			c.printHelp()
		case "listeners":
			c.printListeners()
		case "agents":
			c.printAgents()
		case "chatlog":
			c.printChat()
		case "chat":
			if len(args) == 0 {
				fmt.Println("usage: chat <message>")
				continue
			}
			message := strings.TrimSpace(line[len(fields[0]):])
			if err := c.sendChat(message); err != nil {
				fmt.Printf("failed to send chat message: %v\n", err)
			}
		case "task":
			if err := c.handleTaskCommand(line, args); err != nil {
				fmt.Printf("failed to send task: %v\n", err)
			}
		case "mark":
			if len(args) < 2 {
				fmt.Println("usage: mark <agent-id> <Alive|Dead>")
				continue
			}
			if err := c.markAgent(args[0], args[1]); err != nil {
				fmt.Printf("failed to mark agent: %v\n", err)
			}
		case "exit", "quit":
			cancel()
			return nil
		default:
			fmt.Printf("unknown command: %s\n", cmd)
		}
	}
}

func (c *headlessClient) printHelp() {
	fmt.Println(`Available commands:
  help                Show this help message
  listeners           Display listeners known to the teamserver
  agents              Display active agents
  chatlog             Show the recent chat messages
  chat <message>      Send a chat message to all operators
  task <agent> <command-id> [one-time] [CommandLine text] [key=value ...]
                      Queue a task for an agent. Tokens without '=' become part of CommandLine.
  mark <agent> <Alive|Dead>
  exit|quit           Disconnect from the teamserver`)
}

func (c *headlessClient) printListeners() {
	listeners := c.state.snapshotListeners()
	if len(listeners) == 0 {
		fmt.Println("no listeners available")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPROTOCOL\tBIND\tPORT\tHOSTS\tSTATUS\tUPDATED")
	for _, l := range listeners {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			l.Name, l.Protocol, l.HostBind, l.PortBind, l.Hosts, l.Status, l.UpdatedAt.Format(time.RFC3339))
	}
	tw.Flush()
}

func (c *headlessClient) printAgents() {
	agents := c.state.snapshotAgents()
	if len(agents) == 0 {
		fmt.Println("no agents registered")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tUSER@HOST\tINTERNAL\tEXTERNAL\tPROCESS\tPID\tARCH\tSLEEP\tSTATUS")
	for _, a := range agents {
		host := fmt.Sprintf("%s@%s", a.Username, a.Hostname)
		status := "Dead"
		if a.Active {
			status = "Alive"
		}
		if a.Mark != "" {
			status = a.Mark
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.ID, host, a.InternalIP, a.ExternalIP, a.Process, a.PID, a.Arch, a.Sleep, status)
	}
	tw.Flush()
}

func (c *headlessClient) printChat() {
	messages := c.state.snapshotChat()
	if len(messages) == 0 {
		fmt.Println("no chat messages received")
		return
	}
	for _, m := range messages {
		fmt.Printf("[%s] %s: %s\n", m.Time, m.User, m.Message)
	}
}

func (c *headlessClient) sendChat(message string) error {
	if strings.TrimSpace(message) == "" {
		return errors.New("message cannot be empty")
	}
	info := map[string]any{
		c.username: base64.StdEncoding.EncodeToString([]byte(message)),
	}
	pk := packager.Package{
		Head: packager.Head{
			Event: packager.Type.Chat.Type,
			User:  c.username,
			Time:  time.Now().Format("15:04:05"),
		},
		Body: packager.Body{
			SubEvent: packager.Type.Chat.NewMessage,
			Info:     info,
		},
	}
	return c.sendPackage(pk)
}

func (c *headlessClient) handleTaskCommand(line string, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: task <agent-id> <command-id> [one-time] [CommandLine text] [key=value ...]")
	}
	agentID := args[0]
	commandID := args[1]
	if !c.state.agentExists(agentID) {
		return fmt.Errorf("unknown agent %s", agentID)
	}

	info := map[string]any{
		"DemonID":   agentID,
		"CommandID": commandID,
		"TaskID":    fmt.Sprintf("%08x", rand.Uint32()),
	}

	tokens := strings.Fields(line)
	var commandLineParts []string
	oneTime := false

	for _, token := range tokens[3:] {
		if strings.EqualFold(token, "one-time") {
			oneTime = true
			continue
		}
		if strings.Contains(token, "=") {
			parts := strings.SplitN(token, "=", 2)
			key := parts[0]
			value := parts[1]
			info[key] = value
		} else {
			commandLineParts = append(commandLineParts, token)
		}
	}

	if _, ok := info["CommandLine"]; !ok && len(commandLineParts) > 0 {
		info["CommandLine"] = strings.Join(commandLineParts, " ")
	}

	pk := packager.Package{
		Head: packager.Head{
			Event:   packager.Type.Session.Type,
			User:    c.username,
			Time:    time.Now().Format("02/01/2006 15:04:05"),
			OneTime: "false",
		},
		Body: packager.Body{
			SubEvent: packager.Type.Session.Input,
			Info:     info,
		},
	}
	if oneTime {
		pk.Head.OneTime = "true"
	}

	if err := c.sendPackage(pk); err != nil {
		return err
	}

	c.printf("queued command %s for agent %s (task %s)", commandID, agentID, info["TaskID"])
	return nil
}

func (c *headlessClient) markAgent(agentID, mark string) error {
	status := strings.Title(strings.ToLower(mark))
	if status != "Alive" && status != "Dead" {
		return errors.New("mark must be Alive or Dead")
	}

	pk := packager.Package{
		Head: packager.Head{
			Event: packager.Type.Session.Type,
			User:  c.username,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},
		Body: packager.Body{
			SubEvent: packager.Type.Session.MarkAsDead,
			Info: map[string]any{
				"AgentID": agentID,
				"Marked":  status,
			},
		},
	}
	return c.sendPackage(pk)
}

func (c *headlessClient) Close() error {
	_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return c.conn.Close()
}

func (c *headlessClient) printf(format string, args ...any) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func (s *clientState) snapshotListeners() []listenerSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]listenerSummary, 0, len(s.listeners))
	for _, l := range s.listeners {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *clientState) snapshotAgents() []*agentSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*agentSummary, 0, len(s.agents))
	for _, a := range s.agents {
		copy := *a
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *clientState) snapshotChat() []chatMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]chatMessage, len(s.chat))
	copy(out, s.chat)
	return out
}

func (s *clientState) agentExists(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.agents[id]
	return ok
}

func mapToStringMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch val := v.(type) {
		case string:
			out[k] = val
		case fmt.Stringer:
			out[k] = val.String()
		case float64:
			out[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case int:
			out[k] = strconv.Itoa(val)
		case bool:
			out[k] = strconv.FormatBool(val)
		case map[string]any:
			if data, err := json.Marshal(val); err == nil {
				out[k] = string(data)
			}
		default:
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}

func stringValue(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return strconv.FormatFloat(val, 'f', -1, 64)
		case int:
			return strconv.Itoa(val)
		case bool:
			return strconv.FormatBool(val)
		case json.Number:
			return val.String()
		case map[string]any:
			if data, err := json.Marshal(val); err == nil {
				return string(data)
			}
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}
