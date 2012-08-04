CC := gcc

all:
	bin/waf build

clean:
	bin/waf clean

distclean:
	bin/waf distclean

ctags:
	ctags `find -name \*.[ch]`

