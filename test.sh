#!/bin/bash
EFI_DIR=""
EFI=$(find -name rebirthloongarch64.efi)

if [ "x$EFI" == "x" ];then
    exit
fi

EFI_DIR=$(dirname $EFI)

cat > ${EFI_DIR}/startup.nsh << EOF
@echo -off
if exist fs0:\rebirthloongarch64.efi then
fs0:\rebirthloongarch64.efi
endif
EOF

#cat > ${EFI_DIR}/rebirth.conf << EOF
#title test
#linux   /vmlinuz
#initrd  /initrd.img
#cmdline root=/dev/mem loglevel=7 console=ttyS0,115200
#EOF
#
#cp /boot/vmlinuz-linux ${EFI_DIR}/vmlinuz
#cp /boot/initramfs-linux.img ${EFI_DIR}/initrd.img
cp vmlinuz.unsigned.efi ${EFI_DIR}/rebirthloong64.efi

qemu-system-loongarch64 \
    -m 4G \
    -cpu la464-loongarch-cpu \
    -machine virt \
    -smp 4 \
    -bios /usr/share/edk2/loongarch64/QEMU_EFI.fd \
    -serial stdio \
    -device virtio-gpu-pci \
    -net nic -net user \
    -device nec-usb-xhci,id=xhci,addr=0x1b \
    -device usb-tablet,id=tablet,bus=xhci.0,port=1 \
    -device usb-kbd,id=keyboard,bus=xhci.0,port=2 \
    -device usb-storage,drive=fat32 -drive file=fat:rw:${EFI_DIR},id=fat32,format=raw,if=none
