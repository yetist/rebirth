CROSS_COMPILE=
PREFIX=/usr/
TARGET=rebirth
OBJS=
ARCH=x86_64

CC= $(CROSS_COMPILE)gcc
AS= $(CROSS_COMPILE)gcc
CPP= $(CROSS_COMPILE)gcc
LD= $(CROSS_COMPILE)ld
OBJDUMP= $(CROSS_COMPILE)objdump
OBJCOPY= $(CROSS_COMPILE)objcopy

# libgcc
LIBGCC= $(shell $(CC) -print-libgcc-file-name)
# Linker script
LDSCRIPT= $(PREFIX)/lib/elf_$(ARCH)_efi.lds
# PE header and startup code
STARTOBJ= $(PREFIX)/lib/crt0-efi-$(ARCH).o
# include header
EFI_INCLUDE= $(PREFIX)/include/efi/
INCLUDES= -I. \
	-I$(EFI_INCLUDE) \
	-I$(EFI_INCLUDE)/$(ARCH) \
	-I$(EFI_INCLUDE)/protocol

# CFLAGS
CFLAGS= -DCONFIG_$(ARCH) -DGNU_EFI_USE_MS_ABI \
 	-mno-red-zone -fpic -D__KERNEL__ \
	-maccumulate-outgoing-args --std=c11 \
	-Wall -Wextra -Werror \
	-fshort-wchar -fno-strict-aliasing \
	-fno-merge-all-constants -ffreestanding \
	-fno-stack-protector -fno-stack-check
# LDFLAGS
LDFLAGS= -nostdlib --warn-common --no-undefined \
	--fatal-warnings --build-id=sha1 \
	-shared -Bsymbolic
# set EFI_SUBSYSTEM: Application(0x0a)
LDFLAGS+= --defsym=EFI_SUBSYSTEM=0x0a
LDFLAGS+=-L$(PREFIX)/lib


####### rules #########

all: $(TARGET).efi

# rebuild shared object to PE binary
$(TARGET).efi: $(TARGET).so
	$(OBJCOPY)	-j .text	\
			-j .sdata	\
			-j .data	\
			-j .dynamic	\
			-j .dynsym	\
			-j .rel		\
			-j .rela	\
			-j .rel.*	\
			-j .rela.*	\
			-j .rel*	\
			-j .rela* 	\
			-j .reloc 	\
			-O binary  \
			--target efi-app-x86_64 \
			$(TARGET).so $@

# build shared object
$(TARGET).so: $(TARGET).o $(OBJS)
	$(LD) $(LDFLAGS) $(STARTOBJ) $^ -o $@	\
		-lefi -lgnuefi $(LIBGCC) 			\
		-T $(LDSCRIPT)


%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# clean rule
.PHONY: clean
clean:
	rm -f *.o *.so s*.efi
