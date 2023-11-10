#!/bin/bash
EFI_DIR=""
EFI=$(find -name rebirthloongarch64.efi)

if [ "x$EFI" == "x" ];then
    exit
else
    EFI_DIR=$(dirname $EFI)
fi

cat > ${EFI_DIR}/startup.nsh << EOF
@echo -off
if exist fs0:\rebirthloongarch64.efi then
fs0:\rebirthloongarch64.efi
endif
EOF

qemu-system-loongarch64 \
    -m 4G \
    -cpu la464-loongarch-cpu \
    -machine virt \
    -smp 1 \
    -bios /usr/share/edk2/loongarch64/QEMU_EFI.fd \
    -serial stdio \
    -vga std \
    -net nic -net user \
    -device nec-usb-xhci,id=xhci,addr=0x1b \
    -device usb-tablet,id=tablet,bus=xhci.0,port=1 \
    -device usb-kbd,id=keyboard,bus=xhci.0,port=2 \
    -device usb-storage,drive=fat32 -drive file=fat:rw:${EFI_DIR},id=fat32,format=raw,if=none
