# Environment variables / Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g

# Files and targets
TARGET = pe_analyzer
SRCS = main.c pe_analyzer.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile each source file into an object file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up the workspace
clean:
	rm -f $(OBJS) $(TARGET)