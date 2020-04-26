#!/bin/sh

#sudo ./sample_plugin/temu -kernel-kqemu -snapshot -net nic,vlan=0 -net tap,vlan=0,ifname=tap0,script=/etc/qemu-ifup -hda #WINXPSP2 -m 512 -monitor stdio

#sudo gdb --args ./sample_plugin/temu -kernel-kqemu -net nic,vlan=0 -net tap,vlan=0,ifname=tap0,script=/etc/qemu-ifup -hda #WINXPSP2 -m 512 -k en-us -cdrom /home/hhui/Studies/Crack_New_Year_Presents_2009.iso -monitor stdio

sudo ./sample_plugin/temu -kernel-kqemu -net nic,vlan=0 -net tap,vlan=0,ifname=tap0,script=/etc/qemu-ifup -hda WINXPSP2 -m 1024 -k en-us -cdrom /home/hhui/Studies/Crack_New_Year_Presents_2009.iso -monitor stdio
