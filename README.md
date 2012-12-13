rlm_ftress
==========

4TRESS plugin for [FreeRADIUS](http://freeradius.org)

```
$ cd ~/src
$ wget ftp://ftp.freeradius.org/pub/radius/freeradius-1.1.8.tar.bz2
$ tar -jxvf freeradius-1.1.8.tar.bz2
$ cd freeradius-1.1.8/src/modules
$ git clone git://github.com/mbohun/rlm_ftress.git
$ echo "rlm_ftress" >> stable


```
$ cd rlm_ftress
# get/copy the QuickStartAPI library (either the static lib ftress.a, or the shared lib ftress.so)
#
$ cp ~/QuickStartAPI/ftress.a .
$ ./autogen.sh
```

```
$ cd ~/src/freeradius-1.1.8
$ ./configure --prefix=/opt/freeradius-1.1.8
```

```
...

checking for fgetspent... yes
checking for fgetgrent... yes
configure: creating ./config.status
config.status: creating Makefile
config.status: creating config.h
config.status: config.h is unchanged
=== configuring in src/modules/rlm_checkval (/home/martin/src/freeradius-1.1.8/src/modules/rlm_checkval)
configure: running /bin/sh ./configure '--prefix=/opt/freeradius-1.1.8'  '--enable-ltdl-install' --cache-file=/dev/null --srcdir=.
configure: creating ./config.status
config.status: creating Makefile
=== configuring in src/modules/rlm_ftress (/home/martin/src/freeradius-1.1.8/src/modules/rlm_ftress)
configure: running /bin/sh ./configure '--prefix=/opt/freeradius-1.1.8'  '--enable-ltdl-install' --cache-file=/dev/null --srcdir=.
configure: WARNING: unrecognized options: --enable-ltdl-install
checking for gcc... gcc
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
checking for suffix of executables... 
checking whether we are cross compiling... no
checking for suffix of object files... o
checking whether we are using the GNU C compiler... yes
checking whether gcc accepts -g... yes
checking for gcc option to accept ISO C89... none needed
checking how to run the C preprocessor... gcc -E
configure: creating ./config.status
config.status: creating Makefile
configure: WARNING: unrecognized options: --enable-ltdl-install
[martin@firewolf freeradius-1.1.8]$ 
```

```
$ make
$ sudo make install
```
