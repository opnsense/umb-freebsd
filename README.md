umb(4) for FreeBSD
==================

About umb(4)
------------

umb(4) is a kernel driver for USB MBIM devices.

MBIM devices establish connections via cellular networks such as GPRS, UMTS, and
LTE. They appear as a regular point-to-point network interface, transporting IP
frames.

Required configuration parameters like PIN and APN have to be set with
umbctl(8). Once the SIM card has been unlocked with the correct PIN, it will
remain in this state until the MBIM device is power-cycled. In case the device
is connected to an "always-on" USB port, it may be possible to connect to a
provider without entering the PIN again even if the system was rebooted.

For more information, please refer to the umb(4) and umbctl(8) manual pages.

Building the code
-----------------

Thanks to the Makefiles provided, the following command should be sufficient to
build both the kernel module `if_umb.kmod` as well as the user-land
configuration tool `umbctl`:

    $ make

Installing the code
-------------------

The following command should be sufficient to install both the kernel module
`if_umb.kmod` as well as the user-land configuration tool `umbctl`:

    $ make install

Documentation
-------------

A manual page is available for the user-land configuration tool, `umbctl`:

    $ man ./sbin/umbctl/umbctl.8

Integration with OPNsense
-------------------------

It is possible to create a package for direct deployment onto OPNsense:

    $ make package

This will create a package called `os-umb-$VERSION.txz` in the
`plugin/umb/work/pkg` folder. This can then be installed in OPNsense directly:

    # pkg add os-umb-$VERSION.txz

