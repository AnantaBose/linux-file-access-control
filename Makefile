.RECIPEPREFIX = >
CC     = gcc
CFLAGS = -Wall -Wextra -Iinclude
SRC    = $(wildcard src/*.c)
OBJ    = $(SRC:.c=.o)
TARGET = filemgr

all: $(TARGET)

$(TARGET): $(OBJ)
> $(CC) $(CFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c
> $(CC) $(CFLAGS) -c $< -o $@
$(OBJ): $(wildcard include/*.h)

clean:
> rm -f $(OBJ) $(TARGET)

.PHONY: all clean
