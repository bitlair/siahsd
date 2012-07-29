CC := gcc

# Enable for debug
CFLAGS := -g -ggdb -std=c99 -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wstrict-prototypes -Werror

INCLUDES := -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include

siahsd_LIB := -ltalloc -ldbi -lglib-2.0
siahsd_OBJ := sia.o siahsd.o

OBJ := $(siahsd_OBJ)

binaries := siahsd

all:	$(binaries)

clean:
	rm -f $(binaries)
	rm -f $(OBJ)
	rm -f $(OBJ:.o=.d)

distclean: clean
	rm -f tags


siahsd: $(siahsd_OBJ)
	@echo Linking $@
	@$(CC) $(siahsd_OBJ) $(siahsd_LIB) -o siahsd

ctags:
	ctags `find -name \*.[ch]`

%.o: %.c
	@echo Compiling $*.c
	@$(CC) -c $(CFLAGS) $(INCLUDES) -o $*.o $<
	@$(CC) -MM $(CFLAGS) -MT $*.o $(INCLUDES) -o $*.d $<

-include $(OBJ:.o=.d)
