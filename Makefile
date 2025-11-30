PROGRAM = ft_nmap
SRC_DIR= src
OBJECTS_DIR = objects
HEADERS_DIR = headers

SOURCES = $(addprefix $(SRC_DIR)/, main.c net.c resources.c pcap_utils.c utils.c gateway.c host_discovery.c scans.c)
HEADERS = $(addprefix $(HEADERS_DIR)/, net.h resources.h color_output.h debug.h pcap_utils.h utils.h gateway.h host_discovery.h scans.h)
# the function syntax is function arg1, arg2, arg3
# to call a function in makefile, use $(function arg1, arg2, arg3) - unwrappe like variables
# here arg1 - find all files that have name pattern src/*****.c
# arg2 repleace files according to found pattern with patter in arg 2 - objects/*****.o
# arg3 - the list of files to be processed
# pay attention to % wildcard (not to confuse with * wildcard)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES))

CFLAGS = -g -Wall -Wextra -Werror

ifdef DEBUG
    CFLAGS += -DDEBUG=1
else
    CFLAGS += -DDEBUG=0
endif

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	gcc -o $(PROGRAM) $(OBJECTS) -lpcap

$(OBJECTS_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) $(OBJECTS_DIR)
	gcc -c $(CFLAGS) -I$(HEADERS_DIR) $< -o $@ # -c means compile only, produce an object file

$(OBJECTS_DIR):
	mkdir -p $(OBJECTS_DIR)

clean:
	rm -f $(OBJECTS)

fclean:
	rm -f $(PROGRAM)

re: clean fclean all

debug: 
	make DEBUG=1 re