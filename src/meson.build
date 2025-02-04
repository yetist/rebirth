# SPDX-License-Identifier: LGPL-2.1-or-later

efi_config_h_dir = meson.current_build_dir()

libefitest = static_library(
        'efitest',
        files(
                'efi-string.c',
        ),
        build_by_default : false,
        include_directories : [
                include_directories('.'),
        ],
        )

efitest_base = {
        'link_with' : [
                libefitest,
        ],
}
efi_test_template = efitest_base
efi_fuzz_template = efitest_base

efi_conf = configuration_data()
efi_conf.set10('ENABLE_TPM', true)
if get_option('buildtype') == 'debug'
  efi_conf.set10('EFI_DEBUG', true)
endif

foreach ctype : ['color-normal', 'color-entry', 'color-highlight', 'color-edit']
        c = get_option('efi-' + ctype).split(',')
        efi_conf.set(ctype.underscorify().to_upper(), 'EFI_TEXT_ATTR(@0@, @1@)'.format(
                'EFI_' + c[0].strip().underscorify().to_upper(),
                'EFI_' + c[1].strip().underscorify().to_upper()))
endforeach

summary({'UEFI architectures' : efi_arch + (efi_arch_alt == '' ? '' : ', ' + efi_arch_alt)},
        section : 'UEFI')

configure_file(
        output : 'efi_config.h',
        configuration : efi_conf)

############################################################

efi_includes = [
        include_directories('.'),
]

efi_c_args = [
        '-DSD_BOOT=1',
        '-ffreestanding',
        '-fno-strict-aliasing',
        '-fshort-wchar',
        '-include', 'efi_config.h',
]

efi_c_args += cc.get_supported_arguments(
        '-fwide-exec-charset=UCS2',
        # gcc docs says this is required for ms_abi to work correctly.
        '-maccumulate-outgoing-args',
        '-mstack-protector-guard=global',
)

efi_c_ld_args = [
        '-lgcc',
        '-nostdlib',
        '-static-pie',
        '-Wl,--entry=efi_main',
        '-Wl,--fatal-warnings',

        '-Wl,-static,-pie,--no-dynamic-linker,-z,text',

        # EFI has 4KiB pages.
        '-z', 'common-page-size=4096',
        '-z', 'max-page-size=4096',

        '-z', 'noexecstack',
        '-z', 'relro',
        '-z', 'separate-code',
]

efi_c_ld_args += cc.get_supported_link_arguments(
        # binutils >= 2.38
        '-Wl,-z,nopack-relative-relocs',
)

# efi_c_args is explicitly passed to targets so that they can override distro-provided flags
# that should not be used for EFI binaries.
efi_disabled_c_args = cc.get_supported_arguments(
        '-fcf-protection=none',
        '-fno-asynchronous-unwind-tables',
        '-fno-exceptions',
        '-fno-unwind-tables',
)
efi_override_options = [
        'b_coverage=false',
        'b_pgo=off',
]

if get_option('b_sanitize') == 'undefined'
        efi_disabled_c_args += cc.get_supported_arguments('-fno-sanitize-link-runtime')
else
        efi_disabled_c_args += cc.get_supported_arguments('-fno-sanitize=all')
        efi_override_options += 'b_sanitize=none'
endif

efi_c_args += efi_disabled_c_args
efi_c_ld_args += efi_disabled_c_args

if cc.get_id() == 'clang'
        # clang is too picky sometimes.
        efi_c_args += '-Wno-unused-command-line-argument'
        efi_c_ld_args += '-Wno-unused-command-line-argument'
endif

efi_arch_c_args = {
        'aarch64' : ['-mgeneral-regs-only'],
        'arm'     : ['-mgeneral-regs-only'],
        # Pass -m64/32 explicitly to make building on x32 work.
        'x86_64'  : ['-m64', '-march=x86-64', '-mno-red-zone', '-mgeneral-regs-only'],
        'x86'     : ['-m32', '-march=i686', '-mgeneral-regs-only', '-malign-double'],
}
efi_arch_c_ld_args = {
        # libgcc is not compiled with -fshort-wchar, but it does not use it anyways,
        # so it's fine to link against it.
        'arm'    : cc.get_supported_link_arguments('-Wl,--no-wchar-size-warning'),
        'x86_64' : ['-m64'],
        'x86'    : ['-m32'],
}

linker_sanity_code = 'void a(void) {}; void _start(void) { a(); }'
linker_sanity_args = ['-nostdlib', '-Wl,--fatal-warnings']
if not cc.links(linker_sanity_code,
                name : 'linker supports -static-pie',
                args : [linker_sanity_args, '-static-pie'])
        error('Linker does not support -static-pie.')
endif

# https://github.com/llvm/llvm-project/issues/67152
if not cc.links(linker_sanity_code,
                name : 'linker supports LTO with -nostdlib',
                args : [linker_sanity_args, '-flto'])
        efi_c_args += '-fno-lto'
        efi_c_ld_args += '-fno-lto'
endif

############################################################

libefi_sources = files(
        'console.c',
        'device-path-util.c',
        'devicetree.c',
        'drivers.c',
        'efi-string.c',
        'graphics.c',
        'initrd.c',
        'log.c',
        'measure.c',
        'part-discovery.c',
        'pe.c',
        'random-seed.c',
        'secure-boot.c',
        'shim.c',
        'ticks.c',
        'util.c',
        'vmm.c',
        'sha256.c',
        'string-util-fundamental.c',
        'efivars-fundamental.c',
        'uki.c',
        'bootspec-fundamental.c',
)

rebirth_boot_sources = files(
        'boot.c',
)

if get_option('b_sanitize') == 'undefined'
        libefi_sources += files('ubsan.c')
endif

boot_targets = []
efi_elf_binaries = []
efi_archspecs = [
        {
                'arch' : efi_arch,
                'c_args' : [
                        efi_c_args,
                        '-DEFI_MACHINE_TYPE_NAME="' + efi_arch + '"',
                        efi_arch_c_args.get(host_machine.cpu_family(), []),
                ],
                'link_args' : [
                        efi_c_ld_args,
                        efi_arch_c_ld_args.get(host_machine.cpu_family(), []),
                ],
        },
]
if efi_arch_alt != ''
        efi_archspecs += {
                'arch' : efi_arch_alt,
                'c_args' : [
                        efi_c_args,
                        '-DEFI_MACHINE_TYPE_NAME="' + efi_arch_alt + '"',
                        efi_arch_c_args.get(efi_cpu_family_alt, []),
                ],
                'link_args' : [
                        efi_c_ld_args,
                        efi_arch_c_ld_args.get(efi_cpu_family_alt, []),
                ],
        }
endif

foreach archspec : efi_archspecs
        libefi = static_library(
                'efi' + archspec['arch'],
                libefi_sources,
                include_directories : efi_includes,
                c_args : archspec['c_args'],
                gnu_symbol_visibility : 'hidden',
                override_options : efi_override_options,
                pic : true)

        kwargs = {
                'include_directories' : efi_includes,
                'c_args' : archspec['c_args'],
                'link_args' : archspec['link_args'],
                'gnu_symbol_visibility' : 'hidden',
                'override_options' : efi_override_options,
                'pie' : true,
        }

        efi_elf_binaries += executable(
                'rebirth' + archspec['arch'],
                sources : [rebirth_boot_sources],
                link_with : libefi,
                name_suffix : 'elf',
                kwargs : kwargs)
endforeach

foreach efi_elf_binary : efi_elf_binaries
        name = efi_elf_binary.name()
        name += name.startswith('rebirth') ? '.efi' : '.efi.stub'
        # For the addon, given it's empty, we need to explicitly reserve space in the header to account for
        # the sections that ukify will add.
        minimum_sections = name.endswith('.stub') ? '15' : '0'
        exe = custom_target(
                name,
                output : name,
                input : efi_elf_binary,
                install_tag : 'rebirth',
                command : [
                        elf2efi_py,
                        '--version-major=' + meson.project_version(),
                        '--version-minor=0',
                        '--efi-major=1',
                        '--efi-minor=1',
                        '--subsystem=10',
                        '--minimum-sections=' + minimum_sections,
                        '--copy-sections=.sbat,.sdmagic,.osrel',
                        '@INPUT@',
                        '@OUTPUT@',
                ])
        boot_targets += exe
endforeach

alias_target('rebirth', boot_targets)
