CC		:= gcc
CFLAGS 		:= -s -static -Wall -Wextra -std=c99
OBJS 		:= main.o sha256.o
LIBS 		:= -lz 
TARGET 		:= reself

.PHONY: all clean $(TARGET)
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)  -static -static-libgcc
%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@ -static -static-libgcc 
clean:
	@$(RM) $(OBJS) $(TARGET)
