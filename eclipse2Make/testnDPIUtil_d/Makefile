executable=testnDPIUtil_s
obj=myUtil.o ndpi_util.o testnDPIUtil.o 
CFLAGS = -lpcap -lndpi -I/usr/local/include/libndpi-2.1.0/libndpi/

all: $(obj)
	$(CC) -o $(executable) $(obj) $(CFLAGS)


%.o : %.c
	$(CC) -c $(CFLAGS)  $< -o $@

clean:
	$(RM) *.o $(executable)
