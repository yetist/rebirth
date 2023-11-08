# SPDX-License-Identifier: LGPL-2.1-or-later

project('systemd', 'c',
        version : '254',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'prefix=/usr',
                'sysconfdir=/etc',
                'localstatedir=/var',
                'warning_level=2',
        ],
        meson_version : '>= 0.60.0',
       )

libsystemd_version = '0.37.0'
libudev_version = '1.7.7'

conf = configuration_data()
conf.set_quoted('PROJECT_URL', 'https://systemd.io/')
conf.set('PROJECT_VERSION', meson.project_version(),
         description : 'Numerical project version (used where a simple number is expected)')

project_source_root = meson.current_source_dir()
project_build_root = meson.current_build_dir()
relative_source_path = run_command('realpath',
                                   '--relative-to=@0@'.format(project_build_root),
                                   project_source_root,
                                   check : true).stdout().strip()
conf.set_quoted('RELATIVE_SOURCE_PATH', relative_source_path)

conf.set10('BUILD_MODE_DEVELOPER', true, description : 'tailor build to development or release builds')
conf.set10('LOG_MESSAGE_VERIFICATION', true)

cc = meson.get_compiler('c')

efi_arch = {
        'aarch64'     : 'aa64',
        'arm'         : 'arm',
        'loongarch32' : 'loongarch32',
        'loongarch64' : 'loongarch64',
        'riscv32'     : 'riscv32',
        'riscv64'     : 'riscv64',
        'x86_64'      : 'x64',
        'x86'         : 'ia32',
}.get(host_machine.cpu_family(), '')

have = true
conf.set10('ENABLE_BOOTLOADER', have)
conf.set_quoted('EFI_MACHINE_TYPE_NAME', have ? efi_arch : '')

efi_arch_alt = ''
efi_cpu_family_alt = ''
elf2efi_py = find_program('tools/elf2efi.py')
boot_stubs = []
subdir('src')
