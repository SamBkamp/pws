FLAGS := -Wall -Wextra -pedantic -ggdb
LIBS := -lcrypto -lssl
FILES := src/main.c src/string_manipulation.c src/connections.c src/file_io.c

.PHONY: all

pws:${FILES}
	cc $^ ${FLAGS} ${CFLAGS} -o $@ ${LIBS}

all: pws
