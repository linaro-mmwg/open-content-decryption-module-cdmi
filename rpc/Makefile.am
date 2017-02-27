RPCGEN = rpcgen

noinst_LIBRARIES = libocdm_rpc.a

# Disable warnings in xdr .c files
# due to "unused variable 'buf'"
AM_CFLAGS += "-Wno-unused-variable"

SUFFIXES = .x .c .h

opencdm_callback_xdr.c: opencdm_callback.x
	 -$(RPCGEN)  $<

opencdm_xdr_xdr.c: opencdm_xdr.x
	 -$(RPCGEN)  $<

opencdm_xdr_svc.c: opencdm_callback_xdr.c
opencdm_callback_clnt.c: opencdm_callback_xdr.c

opencdm_callback_xdr.o: opencdm_callback_xdr.c
opencdm_xdr_xdr.o: opencdm_xdr_xdr.c

libocdm_rpc_a_SOURCES = \
      opencdm_xdr_xdr.c\
      opencdm_xdr_svc.c \
      opencdm_callback_xdr.c \
      opencdm_callback_clnt.c 

#opencdm_xdr.x

EXTRA_DIST = opencdm_callback.x  opencdm_xdr.x

CLEANFILES = *.h *.c *.o
