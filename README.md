rlm_ftress
==========

[4TRESS](http://www.actividentity.com/products/strongauthentication/4TRESSAuthenticationAppliance) plugin for [FreeRADIUS](http://freeradius.org) I wrote back in 2007-2008 while working for [ActivIdentity](http://www.actividentity.com)

![Alt text](https://raw.github.com/mbohun/rlm_ftress/master/doc/rlm_ftress-overview.png "rlm_ftress overview")

## building & installing
Get the FreeRadius server source (the 1.1.x series is supported):
```
$ cd ~/src
$ wget ftp://ftp.freeradius.org/pub/radius/freeradius-1.1.8.tar.bz2
$ tar -jxvf freeradius-1.1.8.tar.bz2
```

Go to the `modules` subdir and clone/checkout/copy in the `rlm_ftress` source: 
```
$ cd freeradius-1.1.8/src/modules
$ git clone git://github.com/mbohun/rlm_ftress.git
```

The `freeradius-1.1.8/src/modules/stable` file is used to specify which FreeRADIUS modules/plugins will be build:
```
$ echo "rlm_ftress" >> stable
```

Go into the `rlm_ftress` module dir and run the `autogen.sh` script to generate the `configure` file (this needs to be done only once):
```
$ cd rlm_ftress
$ ./autogen.sh
```

Go back to the FreeRADIUS top level dir and run a standard `./configure; make; sudo make install` build. Note: The QuickStartAPI library (either the shared libftress.so or the static libftress.a) needs to be available to the linker.
```
$ cd ~/src/freeradius-1.1.8
$ ./configure --prefix=/opt/freeradius-1.1.8
$ make
$ sudo make install
```
