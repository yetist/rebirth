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
