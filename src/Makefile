libipt_CONFUSE.so: libipt_CONFUSE.c
	$(CC) $(CFLAGS) -fPIC -shared libipt_CONFUSE.c $(LDFLAGS) -o libipt_CONFUSE.so

install: libipt_CONFUSE.so
	install -m 0755 libipt_CONFUSE.so $(shell pkg-config xtables --variable=xtlibdir)
