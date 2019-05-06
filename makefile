CC = gcc
OBJS_CLIENT = client.o
OBJS_SERVER = Server.o
EXEC_CLIENT = seker_client
EXEC_SERVER = seker_server
CC_COMP_FLAG = -std=c99 -Wall -g

all: $(EXEC_CLIENT)	$(EXEC_SERVER)
$(EXEC_CLIENT): $(OBJS_CLIENT)
	$(CC) $(OBJS_CLIENT) -o $@
$(EXEC_SERVER): $(OBJS_SERVER)
	$(CC) $(OBJS_SERVER) -o $@
client.o: client.c client.h 
	$(CC) $(CC_COMP_FLAG)  -c $*.c
Server.o: Server.c 
	$(CC) $(CC_COMP_FLAG)  -c $*.c
clean:
	@rm -v $(OBJS_CLIENT) $(OBJS_SERVER)
	@rm -v $(EXEC_CLIENT) $(EXEC_SERVER)