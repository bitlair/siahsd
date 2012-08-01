CC := gcc

# Enable for debug
CFLAGS := -g -ggdb -std=c99 -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wstrict-prototypes

INCLUDES := -I/usr/include -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/samba-4.0

siahsd_LIB := -ltalloc -ldbi -lglib-2.0
siahsd_OBJ := sia.o status.o database.o config.o siahsd.o

secipd_LIB := -ltalloc -ldbi -lglib-2.0 -lndr
secipd_OBJ := sia.o status.o database.o config.o ndr_secip.o secipd.o


OBJ := $(siahsd_OBJ) $(secipd_OBJ)

binaries := siahsd secipd

all:	$(binaries)

clean:
	rm -f $(binaries)
	rm -f $(OBJ)
	rm -f $(OBJ:.o=.d)
	rm -f ndr_*.[ch]
	rm -f secip.h

distclean: clean
	rm -f tags


secipd: $(secipd_OBJ)
	@echo Linking $@
	@$(CC) $(secipd_OBJ) $(secipd_LIB) -o secipd

siahsd: $(siahsd_OBJ)
	@echo Linking $@
	@$(CC) $(siahsd_OBJ) $(siahsd_LIB) -o siahsd

ctags:
	ctags `find -name \*.[ch]`

idl:
	pidl/pidl --ndr-parser=ndr_secip.c secip.idl
	pidl/pidl --header=secip.h secip.idl

%.o: %.c
	@echo Compiling $*.c
	@$(CC) -c $(CFLAGS) $(INCLUDES) -o $*.o $<
	@$(CC) -MM $(CFLAGS) -MT $*.o $(INCLUDES) -o $*.d $<

-include $(OBJ:.o=.d)
