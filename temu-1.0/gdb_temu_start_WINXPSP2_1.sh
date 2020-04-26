#!/bin/sh
#sudo ./sample_plugin/temu -kernel-kqemu -snapshot -hda WINXPSP2 -m 1024 -k en-us -monitor stdio
sudo gdb --args ./sample_plugin/temu -kernel-kqemu -snapshot -hda WINXPSP2_1 -m 512 -k en-us -monitor stdio
