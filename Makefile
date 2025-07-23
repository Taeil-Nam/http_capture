# compiler 
CC		=	gcc

# compile flags
CFLAGS		=	-Werror -Wextra -Wall

# includes
INCLUDES	=	-Iincludes

# sources
SRCS		=	$(wildcard srcs/*.c)

# library
LIBS		=	-lpcap

# target
TARGET		=	https_capture

# target_debug
TARGET_DBG	=	https_capture_dbg

# build rule
all: $(TARGET)

debug: $(TARGET_DBG)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(INCLUDES) $(SRCS) $(LIBS)

$(TARGET_DBG): $(SRCS)
	$(CC) $(CFLAGS) -g -fsanitize=address -o $(TARGET_DBG) $(INCLUDES) $(SRCS) $(LIBS)

clean:
	rm -rf $(TARGET) $(TARGET_DBG)

re:
	make -s clean
	make -s all

.PHONY : all clean re
