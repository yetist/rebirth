/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec-fundamental.h"
#include "console.h"
#include "device-path-util.h"
#include "devicetree.h"
#include "drivers.h"
#include "efivars-fundamental.h"
#include "graphics.h"
#include "initrd.h"
#include "measure.h"
#include "part-discovery.h"
#include "pe.h"
#include "proto/block-io.h"
#include "proto/device-path.h"
#include "proto/simple-text-io.h"
#include "random-seed.h"
#include "sbat.h"
#include "secure-boot.h"
#include "shim.h"
#include "ticks.h"
#include "tpm2-pcr.h"
#include "util.h"
#include "version.h"
#include "vmm.h"

/* Magic string for recognizing our own binaries */
#define SD_MAGIC "#### LoaderInfo: rebirth " VERSION " ####"
DECLARE_NOALLOC_SECTION(".sdmagic", SD_MAGIC);

/* Makes rebirth available from \EFI\Linux\ for testing purposes. */
DECLARE_NOALLOC_SECTION(
                ".osrel",
                "ID=rebirth\n"
                "VERSION=\"" VERSION "\"\n"
                "NAME=\"rebirth " VERSION "\"\n");

DECLARE_SBAT(SBAT_BOOT_SECTION_TEXT);

#define LOADER_CONF_CONTENT_EVENT_TAG_ID UINT32_C(0xf5bc582a)

typedef enum LoaderType {
        LOADER_UNDEFINED,
        LOADER_AUTO,
        LOADER_EFI,
        LOADER_LINUX,         /* Boot loader spec type #1 entries */
        LOADER_UNIFIED_LINUX, /* Boot loader spec type #2 entries */
        LOADER_SECURE_BOOT_KEYS,
        _LOADER_TYPE_MAX,
} LoaderType;

typedef struct {
        char16_t *id;         /* The unique identifier for this entry (typically the filename of the file defining the entry) */
        char16_t *title_show; /* The string to actually display (this is made unique before showing) */
        char16_t *title;      /* The raw (human readable) title string of the entry (not necessarily unique) */
        char16_t *sort_key;   /* The string to use as primary sort key, usually ID= from os-release, possibly suffixed */
        char16_t *version;    /* The raw (human readable) version string of the entry */
        char16_t *machine_id;
        EFI_HANDLE *device;
        LoaderType type;
        char16_t *loader;
        char16_t *devicetree;
        char16_t *options;
        bool options_implied; /* If true, these options are implied if we invoke the PE binary without any parameters (as in: UKI). If false we must specify these options explicitly. */
        char16_t **initrd;
        char16_t key;
        EFI_STATUS (*call)(void);
        int tries_done;
        int tries_left;
        char16_t *path;
        char16_t *current_name;
        char16_t *next_name;
} ConfigEntry;

typedef struct {
        ConfigEntry **entries;
        size_t n_entries;
        size_t idx_default;
        size_t idx_default_efivar;
        uint32_t timeout_sec; /* Actual timeout used (efi_main() override > efivar > config). */
        uint32_t timeout_sec_config;
        uint32_t timeout_sec_efivar;
        char16_t *entry_default_config;
        char16_t *entry_default_efivar;
        char16_t *entry_oneshot;
        char16_t *entry_saved;
        bool editor;
        bool auto_entries;
        bool auto_firmware;
        bool auto_poweroff;
        bool auto_reboot;
        bool reboot_for_bitlocker;
        secure_boot_enroll secure_boot_enroll;
        bool force_menu;
        bool use_saved_entry;
        bool use_saved_entry_efivar;
        int64_t console_mode;
        int64_t console_mode_efivar;
} Config;

/* These values have been chosen so that the transitions the user sees could
 * employ unsigned over-/underflow like this:
 * efivar unset ↔ force menu ↔ no timeout/skip menu ↔ 1 s ↔ 2 s ↔ … */
enum {
        TIMEOUT_MIN         = 1,
        TIMEOUT_MAX         = UINT32_MAX - 2U,
        TIMEOUT_UNSET       = UINT32_MAX - 1U,
        TIMEOUT_MENU_FORCE  = UINT32_MAX,
        TIMEOUT_MENU_HIDDEN = 0,
        TIMEOUT_TYPE_MAX    = UINT32_MAX,
};

enum {
        IDX_MAX = INT16_MAX,
        IDX_INVALID,
};

static EFI_STATUS reboot_system(void) {
        RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}

static void config_add_entry(Config *config, ConfigEntry *entry) {
        assert(config);
        assert(entry);

        /* This is just for paranoia. */
        assert(config->n_entries < IDX_MAX);

        if ((config->n_entries & 15) == 0) {
                config->entries = xrealloc(
                                config->entries,
                                sizeof(void *) * config->n_entries,
                                sizeof(void *) * (config->n_entries + 16));
        }
        config->entries[config->n_entries++] = entry;
}

static void config_entry_free(ConfigEntry *entry) {
        if (!entry)
                return;

        free(entry->id);
        free(entry->title_show);
        free(entry->title);
        free(entry->sort_key);
        free(entry->version);
        free(entry->machine_id);
        free(entry->loader);
        free(entry->devicetree);
        free(entry->options);
        strv_free(entry->initrd);
        free(entry->path);
        free(entry->current_name);
        free(entry->next_name);
        free(entry);
}

static char *line_get_key_value(
                char *content,
                const char *sep,
                size_t *pos,
                char **key_ret,
                char **value_ret) {

        char *line, *value;
        size_t linelen;

        assert(content);
        assert(sep);
        assert(pos);
        assert(key_ret);
        assert(value_ret);

        for (;;) {
                line = content + *pos;
                if (*line == '\0')
                        return NULL;

                linelen = 0;
                while (line[linelen] && !strchr8("\n\r", line[linelen]))
                        linelen++;

                /* move pos to next line */
                *pos += linelen;
                if (content[*pos])
                        (*pos)++;

                /* empty line */
                if (linelen == 0)
                        continue;

                /* terminate line */
                line[linelen] = '\0';

                /* remove leading whitespace */
                while (strchr8(" \t", *line)) {
                        line++;
                        linelen--;
                }

                /* remove trailing whitespace */
                while (linelen > 0 && strchr8(" \t", line[linelen - 1]))
                        linelen--;
                line[linelen] = '\0';

                if (*line == '#')
                        continue;

                /* split key/value */
                value = line;
                while (*value && !strchr8(sep, *value))
                        value++;
                if (*value == '\0')
                        continue;
                *value = '\0';
                value++;
                while (*value && strchr8(sep, *value))
                        value++;

                /* unquote */
                if (value[0] == '"' && line[linelen - 1] == '"') {
                        value++;
                        line[linelen - 1] = '\0';
                }

                *key_ret = line;
                *value_ret = value;
                return line;
        }
}

static EFI_STATUS config_entry_bump_counters(ConfigEntry *entry) {
        _cleanup_free_ char16_t* old_path = NULL, *new_path = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ EFI_FILE_INFO *file_info = NULL;
        size_t file_info_size;
        EFI_STATUS err;

        assert(entry);

        if (entry->tries_left < 0)
                return EFI_SUCCESS;

        if (!entry->path || !entry->current_name || !entry->next_name)
                return EFI_SUCCESS;

        _cleanup_(file_closep) EFI_FILE *root = NULL;
        err = open_volume(entry->device, &root);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening entry root path: %m");

        old_path = xasprintf("%ls\\%ls", entry->path, entry->current_name);

        err = root->Open(root, &handle, old_path, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening boot entry: %m");

        err = get_file_info(handle, &file_info, &file_info_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting boot entry file info: %m");

        /* And rename the file */
        strcpy16(file_info->FileName, entry->next_name);
        err = handle->SetInfo(handle, MAKE_GUID_PTR(EFI_FILE_INFO), file_info_size, file_info);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err, "Failed to rename '%ls' to '%ls', ignoring: %m", old_path, entry->next_name);

        /* Flush everything to disk, just in case… */
        err = handle->Flush(handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error flushing boot entry file info: %m");

        /* Let's tell the OS that we renamed this file, so that it knows what to rename to the counter-less name on
         * success */
        new_path = xasprintf("%ls\\%ls", entry->path, entry->next_name);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderBootCountPath", new_path, 0);

        /* If the file we just renamed is the loader path, then let's update that. */
        if (streq16(entry->loader, old_path)) {
                free(entry->loader);
                entry->loader = TAKE_PTR(new_path);
        }

        return EFI_SUCCESS;
}

static void config_load_rebirth(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir)
{
  ConfigEntry *entry;
  EFI_STATUS err;
  _cleanup_free_ char *content = NULL;
  size_t content_size; /* avoid false maybe-uninitialized warning */
  char *line;
  size_t pos = 0, n_initrd = 0;
  char *key, *value;

  assert(config);
  assert(device);
  assert(root_dir);

  entry = xnew(ConfigEntry, 1);

  *entry = (ConfigEntry) {
      .id = xstrdup16(u"rebirth"),
      .tries_done = -1,
      .tries_left = -1,
  };

  err = file_read(root_dir, u"\\rebirth.conf", 0, 0, &content, &content_size);
  if (err != EFI_SUCCESS)
    return;

  while ((line = line_get_key_value(content, " \t", &pos, &key, &value))) {
      if (streq8(key, "title")) {
          free(entry->title);
          entry->title = xstr8_to_16(value);
          continue;
      }

      if (streq8(key, "linux")) {
          free(entry->loader);
          entry->type = LOADER_LINUX;
          entry->loader = xstr8_to_path(value);
          entry->key = 'l';
          continue;
      }

      if (streq8(key, "initrd")) {
          entry->initrd = xrealloc(
                                   entry->initrd,
                                   n_initrd == 0 ? 0 : (n_initrd + 1) * sizeof(uint16_t *),
                                   (n_initrd + 2) * sizeof(uint16_t *));
          entry->initrd[n_initrd++] = xstr8_to_path(value);
          entry->initrd[n_initrd] = NULL;
          continue;
      }

      if (streq8(key, "cmdline")) {
          _cleanup_free_ char16_t *new = NULL;

          new = xstr8_to_16(value);
          if (entry->options) {
              char16_t *s = xasprintf("%ls %ls", entry->options, new);
              free(entry->options);
              entry->options = s;
          } else
            entry->options = TAKE_PTR(new);

          continue;
      }
  }

  if (entry->type == LOADER_UNDEFINED)
    return;

  /* check existence */
  _cleanup_(file_closep) EFI_FILE *handle = NULL;
  err = root_dir->Open(root_dir, &handle, entry->loader, EFI_FILE_MODE_READ, 0ULL);
  if (err != EFI_SUCCESS) {
      log_error("File does not exists: %ls", entry->loader);
      return;
  }

  entry->device = device;
  config_add_entry(config, entry);
}

static size_t config_entry_find(Config *config, const char16_t *pattern) {
        assert(config);

        /* We expect pattern and entry IDs to be already case folded. */

        if (!pattern)
                return IDX_INVALID;

        for (size_t i = 0; i < config->n_entries; i++)
                if (efi_fnmatch(pattern, config->entries[i]->id))
                        return i;

        return IDX_INVALID;
}

static void config_default_entry_select(Config *config) {
        size_t i;

        assert(config);

        i = config_entry_find(config, config->entry_oneshot);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        i = config_entry_find(config, config->use_saved_entry_efivar ? config->entry_saved : config->entry_default_efivar);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                config->idx_default_efivar = i;
                return;
        }

        if (config->use_saved_entry)
                /* No need to do the same thing twice. */
                i = config->use_saved_entry_efivar ? IDX_INVALID : config_entry_find(config, config->entry_saved);
        else
                i = config_entry_find(config, config->entry_default_config);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        /* select the first suitable entry */
        for (i = 0; i < config->n_entries; i++) {
                if (config->entries[i]->type == LOADER_AUTO || config->entries[i]->call)
                        continue;
                config->idx_default = i;
                return;
        }

        /* If no configured entry to select from was found, enable the menu. */
        config->idx_default = 0;
        if (config->timeout_sec == 0)
                config->timeout_sec = 10;
}

static bool entries_unique(ConfigEntry **entries, bool *unique, size_t n_entries) {
        bool is_unique = true;

        assert(entries);
        assert(unique);

        for (size_t i = 0; i < n_entries; i++)
                for (size_t k = i + 1; k < n_entries; k++) {
                        if (!streq16(entries[i]->title_show, entries[k]->title_show))
                                continue;

                        is_unique = unique[i] = unique[k] = false;
                }

        return is_unique;
}

/* generate a unique title, avoiding non-distinguishable menu entries */
static void config_title_generate(Config *config) {
        assert(config);

        bool unique[config->n_entries];

        /* set title */
        for (size_t i = 0; i < config->n_entries; i++) {
                assert(!config->entries[i]->title_show);
                unique[i] = true;
                config->entries[i]->title_show = xstrdup16(config->entries[i]->title ?: config->entries[i]->id);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add version to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->version)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%ls)", t, config->entries[i]->version);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add machine-id to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->machine_id)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%.8ls)", t, config->entries[i]->machine_id);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add file name to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%ls)", t, config->entries[i]->id);
        }
}

static EFI_STATUS initrd_prepare(
                EFI_FILE *root,
                const ConfigEntry *entry,
                char16_t **ret_options,
                void **ret_initrd,
                size_t *ret_initrd_size) {

        assert(root);
        assert(entry);
        assert(ret_options);
        assert(ret_initrd);
        assert(ret_initrd_size);

        if (entry->type != LOADER_LINUX || !entry->initrd) {
                ret_options = NULL;
                ret_initrd = NULL;
                ret_initrd_size = 0;
                return EFI_SUCCESS;
        }

        /* Note that order of initrds matters. The kernel will only look for microcode updates in the very
         * first one it sees. */

        /* Add initrd= to options for older kernels that do not support LINUX_INITRD_MEDIA. Should be dropped
         * if linux_x86.c is dropped. */
        _cleanup_free_ char16_t *options = NULL;

        EFI_STATUS err;
        size_t size = 0;
        _cleanup_free_ uint8_t *initrd = NULL;

        STRV_FOREACH(i, entry->initrd) {
                _cleanup_free_ char16_t *o = options;
                if (o)
                        options = xasprintf("%ls initrd=%ls", o, *i);
                else
                        options = xasprintf("initrd=%ls", *i);

                _cleanup_(file_closep) EFI_FILE *handle = NULL;
                err = root->Open(root, &handle, *i, EFI_FILE_MODE_READ, 0);
                if (err != EFI_SUCCESS)
                        return err;

                _cleanup_free_ EFI_FILE_INFO *info = NULL;
                err = get_file_info(handle, &info, NULL);
                if (err != EFI_SUCCESS)
                        return err;

                if (info->FileSize == 0) /* Automatically skip over empty files */
                        continue;

                size_t new_size, read_size = info->FileSize;
                if (__builtin_add_overflow(size, read_size, &new_size))
                        return EFI_OUT_OF_RESOURCES;
                initrd = xrealloc(initrd, size, new_size);

                err = chunked_read(handle, &read_size, initrd + size);
                if (err != EFI_SUCCESS)
                        return err;

                /* Make sure the actual read size is what we expected. */
                assert(size + read_size == new_size);
                size = new_size;
        }

        if (entry->options) {
                _cleanup_free_ char16_t *o = options;
                options = xasprintf("%ls %ls", o, entry->options);
        }

        *ret_options = TAKE_PTR(options);
        *ret_initrd = TAKE_PTR(initrd);
        *ret_initrd_size = size;
        return EFI_SUCCESS;
}

static EFI_STATUS image_start(
                EFI_HANDLE parent_image,
                const ConfigEntry *entry) {

        _cleanup_(devicetree_cleanup) struct devicetree_state dtstate = {};
        _cleanup_(unload_imagep) EFI_HANDLE image = NULL;
        _cleanup_free_ EFI_DEVICE_PATH *path = NULL;
        EFI_STATUS err;

        assert(entry);

        /* If this loader entry has a special way to boot, try that first. */
        if (entry->call)
                (void) entry->call();

        _cleanup_(file_closep) EFI_FILE *image_root = NULL;
        err = open_volume(entry->device, &image_root);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening root path: %m");

        err = make_file_device_path(entry->device, entry->loader, &path);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error making file device path: %m");

        size_t initrd_size = 0;
        _cleanup_free_ void *initrd = NULL;
        _cleanup_free_ char16_t *options_initrd = NULL;
        err = initrd_prepare(image_root, entry, &options_initrd, &initrd, &initrd_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error preparing initrd: %m");

        err = shim_load_image(parent_image, path, &image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error loading %ls: %m", entry->loader);

        /* DTBs are loaded by the kernel before ExitBootServices, and they can be used to map and assign
         * arbitrary memory ranges, so skip it when secure boot is enabled as the DTB here is unverified. */
        if (entry->devicetree && !secure_boot_enabled()) {
                err = devicetree_install(&dtstate, image_root, entry->devicetree);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error loading %ls: %m", entry->devicetree);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd, initrd_size, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting LoadedImageProtocol handle: %m");

        /* If we had to append an initrd= entry to the command line, we have to pass it, and measure
         * it. Otherwise, only pass/measure it if it is not implicit anyway (i.e. embedded into the UKI or
         * so). */
        char16_t *options = options_initrd ?: entry->options_implied ? NULL : entry->options;
        if (options) {
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = strsize16(options);

                /* Try to log any options to the TPM, especially to catch manually edited options */
                (void) tpm_log_load_options(options, NULL);
        }

        efivar_set_time_usec(MAKE_GUID_PTR(LOADER), u"LoaderTimeExecUSec", 0);
        err = BS->StartImage(image, NULL, NULL);
        graphics_mode(false);
        if (err == EFI_SUCCESS)
                return EFI_SUCCESS;

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && entry->type == LOADER_LINUX) {
                uint32_t compat_address;

                err = pe_kernel_info(loaded_image->ImageBase, &compat_address);
                if (err != EFI_SUCCESS) {
                        if (err != EFI_UNSUPPORTED)
                                return log_error_status(err, "Error finding kernel compat entry address: %m");
                } else if (compat_address > 0) {
                        EFI_IMAGE_ENTRY_POINT kernel_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);

                        err = kernel_entry(image, ST);
                        graphics_mode(false);
                        if (err == EFI_SUCCESS)
                                return EFI_SUCCESS;
                } else
                        err = EFI_UNSUPPORTED;
        }

        return log_error_status(err, "Failed to execute %ls (%ls): %m", entry->title_show, entry->loader);
}

static void config_free(Config *config) {
        assert(config);
        for (size_t i = 0; i < config->n_entries; i++)
                config_entry_free(config->entries[i]);
        free(config->entries);
        free(config->entry_default_config);
        free(config->entry_default_efivar);
        free(config->entry_oneshot);
        free(config->entry_saved);
}

static void config_write_entries_to_variable(Config *config) {
        _cleanup_free_ char *buffer = NULL;
        size_t sz = 0;
        char *p;

        assert(config);

        for (size_t i = 0; i < config->n_entries; i++)
                sz += strsize16(config->entries[i]->id);

        p = buffer = xmalloc(sz);

        for (size_t i = 0; i < config->n_entries; i++)
                p = mempcpy(p, config->entries[i]->id, strsize16(config->entries[i]->id));

        assert(p == buffer + sz);

        /* Store the full list of discovered entries. */
        (void) efivar_set_raw(MAKE_GUID_PTR(LOADER), u"LoaderEntries", buffer, sz, 0);
}

static void save_selected_entry(const Config *config, const ConfigEntry *entry) {
        assert(config);
        assert(entry);
        assert(entry->loader || !entry->call);

        /* Always export the selected boot entry to the system in a volatile var. */
        (void) efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderEntrySelected", entry->id, 0);

        /* Do not save or delete if this was a oneshot boot. */
        if (streq16(config->entry_oneshot, entry->id))
                return;

        if (config->use_saved_entry_efivar || (!config->entry_default_efivar && config->use_saved_entry)) {
                /* Avoid unnecessary NVRAM writes. */
                if (streq16(config->entry_saved, entry->id))
                        return;

                (void) efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderEntryLastBooted", entry->id, EFI_VARIABLE_NON_VOLATILE);
        } else
                /* Delete the non-volatile var if not needed. */
                (void) efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderEntryLastBooted", EFI_VARIABLE_NON_VOLATILE);
}

static EFI_STATUS secure_boot_discover_keys(Config *config, EFI_FILE *root_dir) {
        EFI_STATUS err;
        _cleanup_(file_closep) EFI_FILE *keys_basedir = NULL;

        if (secure_boot_mode() != SECURE_BOOT_SETUP)
                return EFI_SUCCESS;

        /* the lack of a 'keys' directory is not fatal and is silently ignored */
        err = open_directory(root_dir, u"\\loader\\keys", &keys_basedir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return err;

        for (;;) {
                _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
                size_t dirent_size = 0;
                ConfigEntry *entry = NULL;

                err = readdir(keys_basedir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS || !dirent)
                        return err;

                if (dirent->FileName[0] == '.')
                        continue;

                if (!FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;

                entry = xnew(ConfigEntry, 1);
                *entry = (ConfigEntry) {
                        .id = xasprintf("secure-boot-keys-%ls", dirent->FileName),
                        .title = xasprintf("Enroll Secure Boot keys: %ls", dirent->FileName),
                        .path = xasprintf("\\loader\\keys\\%ls", dirent->FileName),
                        .type = LOADER_SECURE_BOOT_KEYS,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);

                if (IN_SET(config->secure_boot_enroll, ENROLL_IF_SAFE, ENROLL_FORCE) &&
                    strcaseeq16(dirent->FileName, u"auto"))
                        /* if we auto enroll successfully this call does not return, if it fails we still
                         * want to add other potential entries to the menu */
                        secure_boot_enroll_at(root_dir, entry->path, config->secure_boot_enroll == ENROLL_FORCE);
        }

        return EFI_SUCCESS;
}

static void export_variables(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                uint64_t init_usec) {

        static const uint64_t loader_features =
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT |
                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                EFI_LOADER_FEATURE_ENTRY_ONESHOT |
                EFI_LOADER_FEATURE_BOOT_COUNTING |
                EFI_LOADER_FEATURE_XBOOTLDR |
                EFI_LOADER_FEATURE_RANDOM_SEED |
                EFI_LOADER_FEATURE_LOAD_DRIVER |
                EFI_LOADER_FEATURE_SORT_KEY |
                EFI_LOADER_FEATURE_SAVED_ENTRY |
                EFI_LOADER_FEATURE_DEVICETREE |
                EFI_LOADER_FEATURE_SECUREBOOT_ENROLL |
                EFI_LOADER_FEATURE_RETAIN_SHIM |
                0;

        _cleanup_free_ char16_t *infostr = NULL, *typestr = NULL;

        assert(loaded_image);

        efivar_set_time_usec(MAKE_GUID_PTR(LOADER), u"LoaderTimeInitUSec", init_usec);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderInfo", u"rebirth " VERSION, 0);

        infostr = xasprintf("%ls %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", infostr, 0);

        typestr = xasprintf("UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", typestr, 0);

        (void) efivar_set_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", loader_features, 0);

        /* export the device path this image is started from */
        _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
        if (uuid)
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, 0);
}

static void config_load_all_entries(
                Config *config,
                EFI_HANDLE *ret_rebirth_dev,
                EFI_FILE *root_dir) {

        assert(config);
        assert(ret_rebirth_dev);
        assert(root_dir);

        config_load_rebirth(config, ret_rebirth_dev, root_dir);

        /* find if secure boot signing keys exist and autoload them if necessary
        otherwise creates menu entries so that the user can load them manually
        if the secure-boot-enroll variable is set to no (the default), we do not
        even search for keys on the ESP */
        if (config->secure_boot_enroll != ENROLL_OFF)
                secure_boot_discover_keys(config, root_dir);

        if (config->n_entries == 0)
                return;

        config_write_entries_to_variable(config);

        config_title_generate(config);

        /* select entry by configured pattern or EFI LoaderDefaultEntry= variable */
        config_default_entry_select(config);
}

static EFI_STATUS search_rebirth_filesystem (EFI_HANDLE *ret_rebirth_dev, EFI_FILE **ret_rebirth_dir)
{
    _cleanup_free_ EFI_HANDLE *handles = NULL;
    size_t n_handles = 0;
    EFI_STATUS err;

    assert(ret_rebirth_dev);
    assert(ret_rebirth_dir);

    (void) reconnect_all_drivers();
    err = BS->LocateHandleBuffer (
            ByProtocol,
            MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL),
            NULL,
            &n_handles,
            &handles
            );
    if (err != EFI_SUCCESS) {
        log_error("Failed to get list of handles: %m");
        return err;
    }

    for (size_t i = 0; i < n_handles; i++) {
        _cleanup_(file_closep) EFI_FILE *root_dir = NULL, *efi_dir = NULL;
        EFI_DEVICE_PATH *fs;

        err = BS->HandleProtocol(
                handles[i], MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &fs);
        if (err != EFI_SUCCESS)
            return err;

#ifdef EFI_DEBUG
        _cleanup_free_ char16_t *file_path_str = NULL;
        _cleanup_free_ char16_t *uuid = NULL;
        if (device_path_to_str(fs, &file_path_str) != EFI_SUCCESS)
            continue;
        convert_efi_path(file_path_str);
        log_error("Device: %ls", file_path_str);
        uuid = disk_get_part_uuid(handles[i]);
        if (uuid) {
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, 0);
		log_error("uuid: %ls", uuid);
	}
#endif

        err = open_volume(handles[i], &root_dir);
        if (err != EFI_SUCCESS)
            continue;

        /* simple Rebirth check */
        err = root_dir->Open(root_dir, &efi_dir, (char16_t*) u"\\rebirthloong64.efi",
                EFI_FILE_MODE_READ,
                EFI_FILE_READ_ONLY);
        if (err != EFI_SUCCESS)
            continue;

        *ret_rebirth_dev = handles[i];
        *ret_rebirth_dir = TAKE_PTR(root_dir);
        return EFI_SUCCESS;
    }

    if (err != EFI_SUCCESS)
        return EFI_NOT_FOUND;
    return EFI_SUCCESS;
}

static EFI_STATUS run(EFI_HANDLE image) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        _cleanup_(config_free) Config config = {};
        EFI_STATUS err;
        uint64_t init_usec;
        EFI_HANDLE ret_rebirth_dev;

        init_usec = time_usec();

        /* Ask Shim to leave its protocol around, so that the stub can use it to validate PEs.
         * By default, Shim uninstalls its protocol when calling StartImage(). */
        shim_retain_protocol();

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        err = search_rebirth_filesystem(&ret_rebirth_dev, &root_dir);
        if (err != EFI_SUCCESS) {
            log_error("Unable to find the rebirth partition.");
            log_error("=> Restarting the system...");
            log_wait();
            reboot_system();
        }

        //config_load_all_entries(&config, &ret_rebirth_dev, root_dir);
        //if (config.n_entries == 0) {
        //    log_error("The \\rebirth.efi configuration file was not found or is invalid.");
        //    log_error("=> Restarting the system...");
        //    log_wait();
        //    reboot_system();
        //}

        //export_variables(ret_rebirth_dev, init_usec);
        ConfigEntry *entry;

	entry = xnew(ConfigEntry, 1);
	*entry = (ConfigEntry) {
	    .id = xstrdup16(u"rebirth"),
	      .tries_done = -1,
	      .tries_left = -1,
	};

	entry->title = xstr8_to_16(u"Loongson Rebirth");
	//free(entry->loader);
	entry->type = LOADER_LINUX;
	entry->loader = xstr8_to_path(u"\\rebirthloong64.efi");
	entry->key = 'l';
	entry->device = ret_rebirth_dev;

        err = image_start(image, entry);
        if (err != EFI_SUCCESS)
            return err;

        return EFI_SUCCESS;
}

DEFINE_EFI_MAIN_FUNCTION(run, "rebirth", /*wait_for_debugger=*/false);
