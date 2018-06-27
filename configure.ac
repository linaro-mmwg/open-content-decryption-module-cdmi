dnl Process this file with autoconf to produce a configure script.
AC_INIT(linaro-cdmi, 1.0, zoltan.kuscsik@linaro.org)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(cdmi/service.cpp)

AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror])

AC_PROG_CXX
AC_PROG_CC

AM_PROG_AR

AC_PROG_RANLIB


AC_CHECK_PROG(RPCGEN,rpcgen,rpcgen)

AX_CXX_COMPILE_STDCXX_11([noext])

AX_CHECK_COMPILE_FLAG([-std=c++11], [
                        CXXFLAGS="$CXXFLAGS -std=c++11"])
AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=false])

if  test x"$debug" = x"true"; then
  AC_SUBST(AM_CXXFLAGS, "-g3 -O0 -DDEBUG -Werror -Wall")
  AC_SUBST(AM_CFLAGS, "-g3 -O0 -DDEBUG -Werror -Wall")
else
  AC_SUBST(AM_CXXFLAGS, "-O2 -Werror -Wall")
  AC_SUBST(AM_CFLAGS, "-O2 -Werror -Wall")
fi


AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_ARG_ENABLE(threads, AC_HELP_STRING([--enable-threads],
                      [make a threading prog (default is yes)]),
                    ac_enable_threads=$enableval,
                    ac_enable_threads=yes)

if test "$ac_enable_threads" = yes; then
  AC_DEFINE(USE_THREADS, 1, [use threads])
fi

AC_ARG_ENABLE(openssl, AC_HELP_STRING([--enable-openssl],
                      [enable openssl (default is yes)]),
                    ac_enable_openssl=$enableval,
                    ac_enable_openssl=yes)

if test "$ac_enable_openssl" = yes; then
  AC_DEFINE(USE_OPENSSL, 1, [use openssl])
fi

AM_CONDITIONAL(OPENSSL, test $ac_enable_openssl = yes)
AM_CONDITIONAL(THREADS, test $ac_enable_threads = yes)

# Enable Microsoft Playready
AC_ARG_ENABLE(playready, AC_HELP_STRING([--enable-playready],
                      [enable playready CDMI (default is no)]),
                    ac_enable_playready=$enableval,
                    ac_enable_playready=no)

if test "$ac_enable_playready" = yes; then
  AC_DEFINE(USE_PLAYREADY, 1, [use playready])
fi

AM_CONDITIONAL(USE_PLAYREADY_CDMI, test $ac_enable_playready = yes)

AC_ARG_ENABLE(aes-ta, AC_HELP_STRING([--enable-aes-ta],
                      [enable aes TA CDMI (default is no)]),
                    ac_enable_aes_ta=$enableval,
                    ac_enable_aes_ta=no)


if test "$ac_enable_aes_ta" = yes; then
  AC_DEFINE(USE_AES_TA, 1, [enable aes ta])
fi

AM_CONDITIONAL(USE_AES_TA, test $ac_enable_aes_ta = yes)


# Enable Secure Data Path
AC_ARG_ENABLE(sdp, AC_HELP_STRING([--enable-sdp],
                      [enable Secure Data Path (default is no)]),
                    ac_enable_sdp=$enableval,
                    ac_enable_sdp=no)

AM_CONDITIONAL(CFG_SECURE_DATA_PATH, test $ac_enable_sdp = yes)

AC_OUTPUT(Makefile cdmi-stub/Makefile rpc/Makefile cdmi/Makefile)
