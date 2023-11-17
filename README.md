# Rebirth

Rebirth is used for os backup and restore.

The rebirth<arch>.efi read the config file from <ESP>/rebirth.conf.

Here is a example for rebirth.conf:

```
title Hello
linux /vmlinuz
initrd /initrd.img
cmdline root=/dev/sda ...
```

## Build

```
meson setup _build
ninja -C _build rebirth
```

## How to embed into edk2 fd

write the follow in fdf:
```
FILE APPLICATION = 65B4495A-F0CE-4D8C-BB90-D3239276FD4B {
    SECTION PE32 = Platform/Loongson/LoongArchQemuPkg/rebirthloongarch64.efi
}
```
