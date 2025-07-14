# compiler 
CC		=	gcc

# compile flags
CFLAGS		=	-Werror -Wextra -Wall

# includes
INCLUDES	=	-Iincludes

# sources
SRCS		=	srcs/main.c

# target
TARGET		=	http_capture

# 빌드 규칙
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(INCLUDES) $(SRCS)

clean:
	rm -rf $(TARGET)
