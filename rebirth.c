#include <efi.h>
#include <efilib.h>

EFI_SYSTEM_TABLE *sys_table;
EFI_BOOT_SERVICES *boot;
EFI_RUNTIME_SERVICES *runtime;

#define REBIRTH_VERSION_MAJOR 0
#define REBIRTH_VERSION_MINOR 1
static CHAR16 *banner = L"Rebirth %d.%d\n";

/**
 * efi_main - The entry point for the rebirth image.
 * @image: firmware-allocated handle that identifies the image
 * @sys_table: EFI system table
 */
EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *_table)
{
  InitializeLib(image, _table);

  sys_table = _table;
  boot = sys_table->BootServices;
  runtime = sys_table->RuntimeServices;

  if (CheckCrc(sys_table->Hdr.HeaderSize, &sys_table->Hdr) != TRUE)
    return EFI_LOAD_ERROR;

  Print(banner, REBIRTH_VERSION_MAJOR, REBIRTH_VERSION_MINOR);

  return EFI_SUCCESS;
}
