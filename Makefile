# Document Makefile
# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -lrt -pthread

# Executable names
EXEC = rsvp

# Source files
SRC = rsvp_main.c rsvpd.c rsvp_sh.c route_dump.c rsvp_db.c rsvp_msg.c timer_event.c log.c label_mgt.c

# Object files (if you want to create them)
OBJ = $(SRC:.c=.o)

# Header files
HEADERS = rsvp_db.h rsvp_msg.h socket.h timer-event.h log.h rsvp_sh.h

# Default target
all: $(EXEC)

# Rule to build socket1
$(EXEC): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $(EXEC) $(SRC) -lrt

# Optional: Rule to create object files (useful for larger projects)
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -f $(EXEC) $(OBJ)

