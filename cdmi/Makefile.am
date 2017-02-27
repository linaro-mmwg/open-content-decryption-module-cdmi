bin_PROGRAMS = cdmiservice
cdmiservice_SOURCES = service.cpp shmemsem_helper.cpp

if THREADS
AM_CXXFLAGS += -pthread
else
AM_CXXFLAGS +=
endif

cdmiservice_LDADD = ${top_srcdir}/rpc/libocdm_rpc.a

if USE_PLAYREADY_CDMI
include Makefile.playready
else
cdmiservice_LDADD += ${top_srcdir}/cdmi-stub/libcdmi.a
endif

if OPENSSL
cdmiservice_LDADD += -lcrypto -lssl
endif

AM_CXXFLAGS += -std=c++11 \
 	  -I${top_srcdir}/include \
    -I${top_srcdir}/rpc \
	  -I$(top_srcdir)/include/shmemsem/

