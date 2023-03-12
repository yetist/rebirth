#!/bin/sh -x

OVMF_CODE=/usr/share/edk2/x64/OVMF_CODE.fd
OVMF_VARS=/usr/share/edk2/x64/OVMF_VARS.fd
#-nographic

qemu-system-x86_64 -cpu qemu64 -m 512 \
  -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS,readonly=on \
  -serial stdio \
  -net none \
  -hda fat:rw:.
