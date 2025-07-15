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
TARGET		=	http_capture

# build rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(INCLUDES) $(SRCS) $(LIBS)

clean:
	rm -rf $(TARGET)

re:
	make -s clean
	make -s all

.PHONY : all clean re
