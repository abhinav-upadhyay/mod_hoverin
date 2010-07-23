## Define compiler debug flags
AM_CFLAGS = $(CXXDEBUGDEFINES)

## Define the source file for the module
noinst_SCRIPTS = mod_hoverin.so

mod_hoverin.so:
	$(APXS) $(APXS_CXX_OPTIONS) $(INCLUDES) -c mod_hoverin.c

## Define install targets
install: mod_hoverin.so
	$(APXS) -i -a mod_hoverin.la
