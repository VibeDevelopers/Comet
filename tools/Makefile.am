bin_PROGRAMS = comet-mkpasswd comet-mkfingerprint
AM_CFLAGS=$(WARNFLAGS)
AM_CPPFLAGS = $(DEFAULT_INCLUDES) -I../librb/include -I.

comet_mkpasswd_SOURCES = mkpasswd.c
comet_mkpasswd_LDADD = ../librb/src/librb.la

comet_mkfingerprint_SOURCES = mkfingerprint.c
comet_mkfingerprint_LDADD = ../librb/src/librb.la
