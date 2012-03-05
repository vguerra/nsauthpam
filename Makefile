
ifdef INST
	NSHOME   ?=  $(INST)
else
	NSHOME   ?=  ../aolserver
endif

#
# Module name
#
MOD      =  nsauthpam.so

#
# Objects to build.
#
OBJS     = nsauthpam.o

MODLIBS	 = -lpam

include  $(NSHOME)/include/Makefile.module
