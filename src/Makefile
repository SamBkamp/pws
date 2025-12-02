FLAGS := -Wall -Wextra -pedantic -ggdb
LIBS := -lcrypto -lssl
FILES := main.c string_manipulation.c connections.c file_io.c

.PHONY: all

pws:${FILES}
	cc $^ ${FLAGS} -o $@ ${LIBS}

all: pws
