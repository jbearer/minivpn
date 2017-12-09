# MiniVPN

A toy VPN using OpenSSL. For educational use only.
Based on [this tutorial](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/VPN/VPN.pdf) by SEED labs.

## Features

* SSL certificate-based verification of server
* Username/password-based verification of clients
* All network traffic encrypted using AES and signed with SHA-256
* Clients can dynamically change session keys
* Server supports multiple concurrent clients on a single port
* Administrators can add users on the server side

## Limitations

* Server uses a resource-inefficient thread-per-client model. However, the non-blocking state-machine design of the client handling code makes it relatively clean to replace this with a fixed-sized thread pool that multiplexes multiple clients across a single thread.
* Users cannot be removed nor can their passwords be changed. However, the backend infrastructure easily supports this; adding this feature would be mostly a matter of front-end (CLI) development.
* Authenticated clients are trusted completely. While there are no known vulnerabilities through which a client could disrupt the operation of the server or gain access to the server or other clients, there are opportunities for denial-of-service attacks for clients with valid credentials. For example, clients can indirectly cause the server to update its routing table, and thus direct traffic away from its intended destination.

## Usage

First build everything with `make`. You'll probably want to add `minivpn/bin` to your path.

### Server

_Start a server_

```
minivpn-server start <network> <netmask>
```

_Check if the server is running_

```
minivpn-server ping
```

_Add users_

```
minivpn-server user add <username>
```

### Client

_Start a client_

```
minivpn-client start <client-ip> <client-network> <client-netmask>
```

_Check if the client is running_

```
minivpn-client ping
```

_Stop the client_

```
minivpn-client stop
```

_Change the session key and/or initialization vector_

```
minivpn-client update-session --key <file> --iv <file>
```
