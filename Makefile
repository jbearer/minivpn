# ENVIRONMENT VARIABLES
#
# SIMPLETUN_BINARY_DIR  -- Prefix for generated files (default build/)
# SIMPLETUN_LOGS_DIR 	-- Prefix for generated files (default logs/)
#
# SIMPLETUN_PEER 		-- IP address of the peer gateway (mandatory)
# SIMPLETUN_PEER_PORT 	-- UDP port of the peer gateway (default 55555)
# SIMPLETUN_LOCAL_PORT 	-- UDP port of outgoing packets (default 55555)
# SIMPLETUN_NET  		-- Private network IP (mandatory)

INCLUDE_DIRS = -Iinclude

CC = gcc
CC_FLAGS = -Wall -Wextra -Werror -std=gnu99 $(INCLUDE_DIRS)

SSL_LIBS = -lssl -lcrypto

ifdef SIMPLETUN_DEBUG
CC_FLAGS += -DDEBUG -g
endif

ifndef SIMPLETUN_LOGS_DIR
SIMPLETUN_LOGS_DIR = logs
endif

ifndef SIMPLETUN_LOCAL_PORT
SIMPLETUN_LOCAL_PORT = 55555
endif
ifndef SIMPLETUN_PEER_PORT
SIMPLETUN_PEER_PORT = 55555
endif

ifndef SIMPLETUN_KEY
SIMPLETUN_KEY = bin/key
endif
ifndef SIMPLETUN_IV
SIMPLETUN_IV = bin/iv
endif

all: $(SIMPLETUN_LOGS_DIR) simpletun server client

clean:
	rm -f ./bin/key
	rm -f ./bin/iv
	rm -f ./bin/minivpn-server-*
	rm -f ./bin/simpletun
	rm -f ./bin/*.o
	rm -f ./bin/minivpn-client-*
	rm -f ./$(SIMPLETUN_LOGS_DIR)/*.out
	rm -f ./$(SIMPLETUN_LOGS_DIR)/*.err
	! [ -d $(SIMPLETUN_LOGS_DIR) ] || rmdir $(SIMPLETUN_LOGS_DIR)

again: clean all

bin/tunnel.o: src/tunnel.c include/tunnel.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/protocol.o: src/protocol.c include/protocol.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/tcp.o: src/tcp.c include/tcp.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/password.o: src/password.c include/password.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

simpletun: bin/simpletun
bin/simpletun: src/simpletun.c bin/tunnel.o
	$(CC) $(CC_FLAGS) -o $@ $^ $(SSL_LIBS)

bin/server.o: src/server/server.c include/server.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

server: bin/minivpn-server-start bin/minivpn-server-ping bin/minivpn-server-stop bin/minivpn-server-user-add
bin/minivpn-server-%: src/server/%.c bin/server.o bin/tunnel.o bin/protocol.o bin/tcp.o bin/password.o
	$(CC) $(CC_FLAGS) -o $@ $^ $(SSL_LIBS) -lpthread -lncurses -lsqlite3

bin/client.o: src/client/client.c include/client.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

client: bin/minivpn-client-start bin/minivpn-client-ping bin/minivpn-client-stop
bin/minivpn-client-%: src/client/%.c bin/client.o bin/tunnel.o bin/protocol.o bin/tcp.o bin/password.o
	$(CC) $(CC_FLAGS) -o $@ $^ $(SSL_LIBS) -lpthread -lncurses -lsqlite3

tunnel: simpletun simpletun_net simpletun_peer stop_tunnel $(SIMPLETUN_LOGS_DIR) $(SIMPLETUN_KEY) $(SIMPLETUN_IV)
	bin/simpletun --port $(SIMPLETUN_LOCAL_PORT) \
		--peer-ip $(SIMPLETUN_PEER) --peer-port $(SIMPLETUN_PEER_PORT) \
		--encryption-key $(SIMPLETUN_KEY) --encryption-iv $(SIMPLETUN_IV) \
		--network $(SIMPLETUN_NET) --netmask 255.255.255.0 \
		> $(SIMPLETUN_LOGS_DIR)/simpletun.out 2> $(SIMPLETUN_LOGS_DIR)/simpletun.err &

stop_tunnel:
	killall -q -9 simpletun || true # killall returns 1 if no processes were killed
	sleep 1
	! (ps -e | grep simpletun)

$(SIMPLETUN_LOGS_DIR):
	mkdir $@

$(SIMPLETUN_KEY):
	head -c 32 /dev/urandom > $(SIMPLETUN_KEY)

$(SIMPLETUN_IV):
	head -c 16 /dev/urandom > $(SIMPLETUN_IV)

simpletun_peer:
ifndef SIMPLETUN_PEER
	$(error SIMPLETUN_PEER is not set)
endif

simpletun_net:
ifndef SIMPLETUN_NET
	$(error SIMPLETUN_NET is not set)
endif
