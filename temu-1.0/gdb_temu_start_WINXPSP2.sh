#!/bin/sh
sudo gdb --args ./sample_plugin/temu -kernel-kqemu -hda WINXPSP2 -m 512 -k en-us -monitor stdio
#sudo gdb --args ./sample_plugin/temu -kernel-kqemu -hda WINXPSP2 -m 512 -k en-us -soundhw all -monitor stdio
