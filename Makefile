CC := gcc

all:
	@bin/waf build

clean:
	@bin/waf clean

distclean:
	@bin/waf distclean
	@rm tags

ctags:
	@ctags `find -name \*.[ch]`

coverity:
	@if [ -d cov-int ]; then rm -rf cov-int;fi
	@mkdir cov-int
	@cov-build --dir=cov-int bin/waf configure clean build
	@tar cvzf coverity_siahsd.tgz cov-int
	@rm -rf cov-int

