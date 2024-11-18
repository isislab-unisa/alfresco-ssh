# alfresco-ssh
Inspired by: 
- [cs01/pyxtermjs](https://github.com/cs01/pyxtermjs) (used as a base structure)
- [huashengdun/webssh](https://github.com/huashengdun/webssh)

## How does it work
This project uses: 
- [Flask](https://flask.palletsprojects.com/en/stable/) as a web application framework
- [xterm.js](https://xtermjs.org/) to create a client terminal in the browser window of the user
- [Socket.IO](https://socket.io/) for bidirectional and low-latency communication between the browser and the sever (with WebSockets)
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/en/latest/) to access the Socket.IO API from Python

### Create new Session
Prepares the connection by storing the credentials and generating a URL. 
```mermaid
sequenceDiagram
    participant U as User
    participant S as Server

    U->>S: HTTP POST /create-session (credentials)
    S->>S: Generate UUID
    S->>S: Save credentials with key UUID
    S-->>U: JSON {UUID, URL}
```

### Start Session
```mermaid
sequenceDiagram
    participant U as User
    participant S as Server
    participant R as Remote Terminal

    U->>S: HTTP GET /<UUID> (SessionID)
    S->>S: Render Template (HTML, UUID)
    S-->>U: HTML (UUID)
    U->>U: Execute HTML JavaScript
    U->>S: JS: Send ("connect")
    S-->>U: Connected with Web Socket
    U->>S: JS: Send ("start-session", UUID)
    S->>S: Get (credentials, UUID)
    S->>R: Connect to Remote (credentials)
    R-->>S: Paramiko Interactive Shell (ssh session)
    S->>S: Delete (credentials, UUID)
    S->>S: Save (ssh session, SessionID)
    S->>S: Continuously read Remote Terminal output (SessionID)
    S-->>U: Ready to receive inputs
```

Where `UUID` and `SessionID` are not the same:
- `UUID` is the one generated from the `create-session` process
- `SessionID` is the id of the connection with Flask

### Input/Output
```mermaid
sequenceDiagram
    participant U as User
    participant S as Server
    participant R as Remote Terminal

    S->>S: Continuously read Remote Terminal output (SessionID)
    U->>U: Type a key in the terminal
    U->>S: JS: Send ("ssh-input", input)
    S->>R: Send to Remote (input)
    R->>R: Put in Terminal (input)
    R-->>S: Send to Server (output)
    S-->>U: Send ("ssh-output", output)
    U->>U: JS: Replace current output (output)
    
```

The `input` is usually one character long. 
The only exceptions are some special keyboard keys (like the arrow keys).
