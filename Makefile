LIBNAME=	libdeadcafe
SRC=		deadcafe.c
OBJ=		deadcafe.o
HEADER=		
OPENSSL_DIR=	/usr/local/ssl
CC=		gcc
PIC=		-fPIC
CPPFLAGS=	-DENGINE_DYNAMIC_SUPPORT -DFLAT_INC -I$(OPENSSL_DIR)/include
CFLAGS=		-g -O3 -Wall -W $(PIC) $(CPPFLAGS)
AR=		ar r
RANLIB=		ranlib
LIBS=		-L$(OPENSSL_DIR)/lib64 -lcrypto -lc -lgmp
LIB=		$(LIBNAME).a
SHLIB=		$(LIBNAME).so
MKERR=		$(OPENSSL_DIR)/misc/util/mkerr.pl

all:
		@echo 'Please choose a system to build on:'
		@echo ''
		@echo 'tru64:    Tru64 Unix, Digital Unix, Digital OSF/1'
		@echo 'solaris:  Solaris'
		@echo 'irix:     IRIX'
		@echo 'hpux32:   32-bit HP/UX'
		@echo 'hpux64:   64-bit HP/UX'
		@echo 'aix:      AIX'
		@echo 'gnu:      Generic GNU-based system (gcc and GNU ld)'
		@echo ''

FORCE.update:
update:		FORCE.update
		perl $(MKERR) -conf deadcafe.ec -nostatic -staticloader -write deadcafe_err.c

gnu:		$(SHLIB).gnu
tru64:		$(SHLIB).tru64
solaris:	$(SHLIB).solaris
irix:		$(SHLIB).irix
hpux32:		$(SHLIB).hpux32
hpux64:		$(SHLIB).hpux64
aix:		$(SHLIB).aix

$(LIB):		$(OBJ)
		$(AR) $(LIB) $(OBJ)
		- $(RANLIB) $(LIB)

LINK_SO=	\
  ld -r -o $(LIBNAME).o $$ALLSYMSFLAGS $(LIB) && \
  (nm -Pg $(LIBNAME).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB) $(LIBNAME).o $(LIBS))

$(SHLIB).gnu:	$(LIB)
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).gnu
$(SHLIB).tru64:	$(LIB)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).tru64
$(SHLIB).solaris:	$(LIB)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).solaris
$(SHLIB).irix:	$(LIB)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).irix
$(SHLIB).hpux32:	$(LIB)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux32
$(SHLIB).hpux64:	$(LIB)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux64
$(SHLIB).aix:	$(LIB)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).aix

depend:
		sed -e '/^# DO NOT DELETE.*/,$$d' < Makefile > .Makefile.tmp
		echo '# DO NOT DELETE THIS LINE -- make depend depends on it.' >> .Makefile.tmp
		gcc -M $(CFLAGS) $(SRC) >> Makefile.tmp
		perl ../../../util/clean-depend.pl < .Makefile.tmp > .Makefile.new
		rm -f .Makefile.tmp Makefile
		mv .Makefile.new Makefile

dclean:
	perl -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >.Makefile.new
	mv -f .Makefile.new $(MAKEFILE)
	@target=dclean; $(RECURSIVE_MAKE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff $(LIBNAME) $(LIBNAME).* *~
	@target=clean; $(RECURSIVE_MAKE)

# DO NOT DELETE THIS LINE -- make depend depends on it.

deadcafe.o: deadcafe.c deadcafe_err.c deadcafe_err.h
