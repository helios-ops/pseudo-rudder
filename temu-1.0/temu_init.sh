#!/bin/sh
sudo reload udev
sudo depmod -a
sudo modprobe -r kqemu
sudo modprobe kqemu
ls -l /dev/kqemu

