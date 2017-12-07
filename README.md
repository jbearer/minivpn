# MiniVPN

A toy VPN using OpenSSL. For educational use only.
Based on [this tutorial](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/VPN/VPN.pdf) by SEED labs.

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
