INCLUDE_DIRS = -Iinclude

CC = gcc
CC_FLAGS = -Wall -Wextra -Werror -std=gnu99 $(INCLUDE_DIRS)

SSL_LIBS = -lssl -lcrypto

ifdef MINIVPN_DEBUG
CC_FLAGS += -DDEBUG -g
endif

all: $(SIMPLETUN_LOGS_DIR) server client

clean:
	rm -f ./bin/key
	rm -f ./bin/iv
	rm -f ./bin/minivpn-server-*
	rm -f ./bin/*.o
	rm -f ./bin/minivpn-client-*

again: clean all

bin/tunnel.o: src/tunnel.c include/tunnel.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/protocol.o: src/protocol.c include/protocol.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/tcp.o: src/tcp.c include/tcp.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/password.o: src/password.c include/password.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/demon.o: src/demon.c include/demon.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

bin/server.o: src/server/server.c include/server.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

server: bin/minivpn-server-start bin/minivpn-server-ping bin/minivpn-server-stop bin/minivpn-server-user-add
bin/minivpn-server-%: src/server/%.c bin/server.o bin/tunnel.o bin/protocol.o bin/tcp.o bin/password.o bin/demon.o
	$(CC) $(CC_FLAGS) -o $@ $^ $(SSL_LIBS) -lpthread -lncurses -lsqlite3

bin/client.o: src/client/client.c include/client.h
	$(CC) $(CC_FLAGS) -c -o $@ $<

client: bin/minivpn-client-start bin/minivpn-client-ping bin/minivpn-client-stop bin/minivpn-client-update-session
bin/minivpn-client-%: src/client/%.c bin/client.o bin/tunnel.o bin/protocol.o bin/tcp.o bin/password.o
	$(CC) $(CC_FLAGS) -o $@ $^ $(SSL_LIBS) -lpthread -lncurses -lsqlite3
