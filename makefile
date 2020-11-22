###
### Copyright (C) HWPORT.COM
### All rights reserved.
### Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
###

CROSS_COMPILE                ?=#

CC                           :=$(CROSS_COMPILE)gcc#
LD                           :=$(CROSS_COMPILE)ld#
STRIP                        :=$(CROSS_COMPILE)strip#
RM                           :=rm -f#
AR                           :=$(CROSS_COMPILE)ar#

CFLAGS                       :=#
CFLAGS                       +=-Os#
CFLAGS                       +=-pipe#
CFLAGS                       +=-fPIC#
CFLAGS                       +=-fomit-frame-pointer#
CFLAGS                       +=-ansi#
CFLAGS                       +=-Wall -W#
CFLAGS                       +=-Wshadow#
CFLAGS                       +=-Wcast-qual#
CFLAGS                       +=-Wcast-align#
CFLAGS                       +=-Wpointer-arith#
CFLAGS                       +=-Wbad-function-cast#
CFLAGS                       +=-Wstrict-prototypes#
CFLAGS                       +=-Wmissing-prototypes#
CFLAGS                       +=-Wmissing-declarations#
CFLAGS                       +=-Wnested-externs#
CFLAGS                       +=-Winline#
CFLAGS                       +=-Wwrite-strings#
CFLAGS                       +=-Wchar-subscripts#
CFLAGS                       +=-Wformat#
CFLAGS                       +=-Wformat-security#
CFLAGS                       +=-Wimplicit#
CFLAGS                       +=-Wmain#
CFLAGS                       +=-Wmissing-braces#
CFLAGS                       +=-Wnested-externs#
CFLAGS                       +=-Wparentheses#
CFLAGS                       +=-Wredundant-decls#
CFLAGS                       +=-Wreturn-type#
CFLAGS                       +=-Wsequence-point#
CFLAGS                       +=-Wsign-compare#
CFLAGS                       +=-Wswitch#
CFLAGS                       +=-Wuninitialized#
CFLAGS                       +=-Wunknown-pragmas#
CFLAGS                       +=-Wcomment#
CFLAGS                       +=-Wundef#
CFLAGS                       +=-Wunused#
CFLAGS                       +=-Wunreachable-code#
CFLAGS                       +=-Wconversion#
CFLAGS                       +=-Wpadded#

LDFLAGS                      :=-s#

ARFLAGS                      :=rcs#

TARGET                       :=hwport_aria libhwport_aria.so libhwport_aria.so.0 libhwport_aria.so.0.0.0 libhwport_aria.a libhwport_aria.lo#

.PHONY: all clean

all: $(TARGET)

clean:
	$(RM) *.o $(TARGET)

hwport_aria: main.o libhwport_aria.a
	$(CC) $(LDFLAGS) -o $(@) $(^)
	$(STRIP) --remove-section=.comment --remove-section=.note $(@)

libhwport_aria.so libhwport_aria.so.0: libhwport_aria.so.0.0.0
	ln -sf $(<) $(@)

libhwport_aria.so.0.0.0: libhwport_aria.lo
	$(CC) $(LDFLAGS) -shared -Wl,-soname,$(notdir $(@)) -o $(@) $(^)
	$(STRIP) --remove-section=.comment --remove-section=.note $(@)

libhwport_aria.a: aria.o
	$(AR) $(ARFLAGS) $(@) $(^) 

libhwport_aria.lo: aria.o
	$(LD) $(LDFLAGS) -r -o $(@) $(^)

%.o: %.c makefile
	$(CC) $(CFLAGS) -c -o $(@) $(<)

# End of makefile
