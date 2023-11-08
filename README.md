# Rebirth

Rebirth is used for os backup and restore.

The birth<arch>.efi read the config file from <ESP>/rebirth.conf.

Here is a example:

```
title Hello
linux /vmlinuz
initrd /initrd.img
cmdline root=/dev/sda ...
```
