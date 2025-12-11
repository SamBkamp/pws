BUILD_FLAGS := -Wall -Wextra -pedantic -O2
DEV_FLAGS := -Wall -Wextra -pedantic -Werror -ggdb
LIBS := -lcrypto -lssl
FILES := main.c src/pws.c src/string_manipulation.c src/connections.c src/file_io.c

.PHONY: all
.PHONY: dev

pws:${FILES}
	cc $^ ${BUILD_FLAGS} ${CFLAGS} -o $@ ${LIBS}

dev:${FILES}
	cc $^ ${DEV_FLAGS} ${CFLAGS} -o pws ${LIBS}

all: pws
