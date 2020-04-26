#!/bin/sh
#sudo ./sample_plugin/temu -kernel-kqemu -snapshot -hda WINXPSP2 -m 1024 -k en-us -monitor stdio
sudo ./sample_plugin/temu -kernel-kqemu -hda WINXPSP2 -m 512 -k en-us -monitor stdio
