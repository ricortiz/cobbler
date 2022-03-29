"""
Migration from V3.3.1 to V3.3.2
"""
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2022 Dominik Gedon <dgedon@suse.de>
# SPDX-FileCopyrightText: Copyright SUSE LLC


from schema import Optional, Schema, SchemaError

schema = Schema(
    {
        Optional("auto_migrate_settings", default=False): bool,
        Optional("allow_duplicate_hostnames", default=False): bool,
        Optional("allow_duplicate_ips", default=False): bool,
        Optional("allow_duplicate_macs", default=False): bool,
        Optional("allow_dynamic_settings", default=False): bool,
        Optional("always_write_dhcp_entries", default=False): bool,
        Optional("anamon_enabled", default=False): bool,
        Optional("auth_token_expiration", default=3600): int,
        Optional("authn_pam_service", default="login"): str,
        Optional("autoinstall_snippets_dir", default="/var/lib/cobbler/snippets"): str,
        Optional(
            "autoinstall_templates_dir", default="/var/lib/cobbler/templates"
        ): str,
        Optional("bind_chroot_path", default=""): str,
        Optional("bind_zonefile_path", default="@@bind_zonefiles@@"): str,
        Optional("bind_master", default="127.0.0.1"): str,
        Optional(
            "boot_loader_conf_template_dir", default="/etc/cobbler/boot_loader_conf"
        ): str,
        Optional("bootloaders_dir", default="/var/lib/cobbler/loaders"): str,
        Optional(
            "bootloaders_formats",
            default={
                "aarch64": {"binary_name": "grubaa64.efi"},
                "arm": {"binary_name": "bootarm.efi"},
                "arm64-efi": {
                    "binary_name": "grubaa64.efi",
                    "extra_modules": ["efinet"],
                },
                "i386": {"binary_name": "bootia32.efi"},
                "i386-pc-pxe": {
                    "binary_name": "grub.0",
                    "mod_dir": "i386-pc",
                    "extra_modules": ["chain", "pxe", "biosdisk"],
                },
                "i686": {"binary_name": "bootia32.efi"},
                "IA64": {"binary_name": "bootia64.efi"},
                "powerpc-ieee1275": {
                    "binary_name": "grub.ppc64le",
                    "extra_modules": ["net", "ofnet"],
                },
                "x86_64-efi": {
                    "binary_name": "grubx86.efi",
                    "extra_modules": ["chain", "efinet"],
                },
            },
        ): dict,
        Optional(
            "bootloaders_modules",
            default=[
                "btrfs",
                "ext2",
                "xfs",
                "jfs",
                "reiserfs",
                "all_video",
                "boot",
                "cat",
                "configfile",
                "echo",
                "fat",
                "font",
                "gfxmenu",
                "gfxterm",
                "gzio",
                "halt",
                "iso9660",
                "jpeg",
                "linux",
                "loadenv",
                "minicmd",
                "normal",
                "part_apple",
                "part_gpt",
                "part_msdos",
                "password_pbkdf2",
                "png",
                "reboot",
                "search",
                "search_fs_file",
                "search_fs_uuid",
                "search_label",
                "sleep",
                "test",
                "true",
                "video",
                "mdraid09",
                "mdraid1x",
                "lvm",
                "serial",
                "regexp",
                "tr",
                "tftp",
                "http",
                "luks",
                "gcry_rijndael",
                "gcry_sha1",
                "gcry_sha256",
            ],
        ): list,
        Optional("bootloaders_shim_folder", default="@@shim_folder@@"): str,
        Optional("bootloaders_shim_file", default="@@shim_file@@"): str,
        Optional("bootloaders_ipxe_folder", default="@@ipxe_folder@@"): str,
        Optional("syslinux_dir", default="@@syslinux_dir@@"): str,
        Optional("syslinux_memdisk_folder", default="@@memdisk_folder@@"): str,
        Optional("syslinux_pxelinux_folder", default="@@pxelinux_folder@@"): str,
        Optional("grub2_mod_dir", default="/usr/share/grub"): str,
        Optional("grubconfig_dir", default="/var/lib/cobbler/grub_config"): str,
        Optional("build_reporting_enabled", default=False): bool,
        Optional("build_reporting_email", default=["root@localhost"]): [str],
        Optional("build_reporting_ignorelist", default=[]): [str],
        Optional("build_reporting_sender", default=""): str,
        Optional("build_reporting_smtp_server", default="localhost"): str,
        Optional("build_reporting_subject", default=""): str,
        Optional("buildisodir", default="/var/cache/cobbler/buildiso"): str,
        Optional(
            "cheetah_import_whitelist", default=["random", "re", "time", "netaddr"]
        ): [str],
        Optional("client_use_https", default=False): bool,
        Optional("client_use_localhost", default=False): bool,
        Optional("cobbler_master", default=""): str,
        Optional("convert_server_to_ip", default=False): bool,
        Optional("createrepo_flags", default="-c cache -s sha"): str,
        Optional("autoinstall", default="default.ks"): str,
        Optional("default_name_servers", default=[]): [str],
        Optional("default_name_servers_search", default=[]): [str],
        Optional("default_ownership", default=["admin"]): [str],
        Optional(
            "default_password_crypted", default="$1$mF86/UHC$WvcIcX2t6crBz2onWxyac."
        ): str,
        Optional("default_template_type", default="cheetah"): str,
        Optional("default_virt_bridge", default="xenbr0"): str,
        Optional("default_virt_disk_driver", default="raw"): str,
        Optional("default_virt_file_size", default=5): int,
        Optional("default_virt_ram", default=512): int,
        Optional("default_virt_type", default="xenpv"): str,
        Optional("enable_ipxe", default=False): bool,
        Optional("enable_menu", default=True): bool,
        Optional("http_port", default=80): int,
        Optional("iso_template_dir", default="/etc/cobbler/iso"): str,
        Optional("jinja2_includedir", default="/var/lib/cobbler/jinja2"): str,
        Optional("kernel_options", default={}): dict,
        Optional("ldap_anonymous_bind", default=True): bool,
        Optional("ldap_base_dn", default="DC=devel,DC=redhat,DC=com"): str,
        Optional("ldap_port", default=389): int,
        Optional("ldap_search_bind_dn", default=""): str,
        Optional("ldap_search_passwd", default=""): str,
        Optional("ldap_search_prefix", default="uid="): str,
        Optional("ldap_server", default="grimlock.devel.redhat.com"): str,
        Optional("ldap_tls", default=True): bool,
        Optional("ldap_tls_cacertdir", default=""): str,
        Optional("ldap_tls_cacertfile", default=""): str,
        Optional("ldap_tls_certfile", default=""): str,
        Optional("ldap_tls_keyfile", default=""): str,
        Optional("ldap_tls_reqcert", default=""): str,
        Optional("ldap_tls_cipher_suite", default=""): str,
        Optional("bind_manage_ipmi", default=False): bool,
        # TODO: Remove following line
        Optional("manage_dhcp", default=False): bool,
        Optional("manage_dhcp_v4", default=False): bool,
        Optional("manage_dhcp_v6", default=False): bool,
        Optional("manage_dns", default=False): bool,
        Optional("manage_forward_zones", default=[]): [str],
        Optional("manage_reverse_zones", default=[]): [str],
        Optional("manage_genders", False): bool,
        Optional("manage_rsync", default=False): bool,
        Optional("manage_tftpd", default=True): bool,
        Optional("mgmt_classes", default=[]): [str],
        # TODO: Validate Subdict
        Optional("mgmt_parameters", default={"from_cobbler": True}): dict,
        Optional("next_server_v4", default="127.0.0.1"): str,
        Optional("next_server_v6", default="::1"): str,
        Optional("nsupdate_enabled", False): bool,
        Optional("nsupdate_log", default="/var/log/cobbler/nsupdate.log"): str,
        Optional("nsupdate_tsig_algorithm", default="hmac-sha512"): str,
        Optional("nsupdate_tsig_key", default=[]): [str],
        Optional("power_management_default_type", default="ipmilanplus"): str,
        Optional("proxies", default=[]): [str],
        Optional("proxy_url_ext", default=""): str,
        Optional("proxy_url_int", default=""): str,
        Optional("puppet_auto_setup", default=False): bool,
        Optional("puppet_parameterized_classes", default=True): bool,
        Optional("puppet_server", default="puppet"): str,
        Optional("puppet_version", default=2): int,
        Optional("puppetca_path", default="/usr/bin/puppet"): str,
        Optional("pxe_just_once", default=True): bool,
        Optional("nopxe_with_triggers", default=True): bool,
        Optional("redhat_management_permissive", default=False): bool,
        Optional("redhat_management_server", default="xmlrpc.rhn.redhat.com"): str,
        Optional("redhat_management_key", default=""): str,
        Optional("register_new_installs", default=False): bool,
        Optional("remove_old_puppet_certs_automatically", default=False): bool,
        Optional("replicate_repo_rsync_options", default="-avzH"): str,
        Optional("replicate_rsync_options", default="-avzH"): str,
        Optional(
            "reposync_flags", default="--newest-only --delete --refresh --remote-time"
        ): str,
        Optional("reposync_rsync_flags", default="-rltDv --copy-unsafe-links"): str,
        Optional("restart_dhcp", default=True): bool,
        Optional("restart_dns", default=True): bool,
        Optional("run_install_triggers", default=True): bool,
        Optional("scm_track_enabled", default=False): bool,
        Optional("scm_track_mode", default="git"): str,
        Optional("scm_track_author", default="cobbler <cobbler@localhost>"): str,
        Optional("scm_push_script", default="/bin/true"): str,
        Optional("serializer_pretty_json", default=False): bool,
        Optional("server", default="127.0.0.1"): str,
        Optional("sign_puppet_certs_automatically", default=False): bool,
        Optional(
            "signature_path", default="/var/lib/cobbler/distro_signatures.json"
        ): str,
        Optional(
            "signature_url",
            default="https://cobbler.github.io/signatures/3.0.x/latest.json",
        ): str,
        Optional("tftpboot_location", default="@@tftproot@@"): str,
        Optional("virt_auto_boot", default=True): bool,
        Optional("webdir", default="@@webroot@@/cobbler"): str,
        Optional(
            "webdir_whitelist",
            default=[
                "misc",
                "web",
                "webui",
                "localmirror",
                "repo_mirror",
                "distro_mirror",
                "images",
                "links",
                "pub",
                "repo_profile",
                "repo_system",
                "svc",
                "rendered",
                ".link_cache",
            ],
        ): [str],
        Optional("xmlrpc_port", default=25151): int,
        Optional("yum_distro_priority", default=1): int,
        Optional("yum_post_install_mirror", default=True): bool,
        Optional("yumdownloader_flags", default="--resolve"): str,
        Optional("windows_enabled", default=False): bool,
        Optional("windows_template_dir", default="/etc/cobbler/windows"): str,
        Optional("samba_distro_share", default="DISTRO"): str,
    },
    ignore_extra_keys=False,
)


def validate(settings: dict) -> bool:
    """
    Checks that a given settings dict is valid according to the reference V3.4.0 schema ``schema``.

    :param settings: The settings dict to validate.
    :return: True if valid settings dict otherwise False.
    """
    try:
        schema.validate(settings)
    except SchemaError:
        return False
    return True


def normalize(settings: dict) -> dict:
    """
    If data in ``settings`` is valid the validated data is returned.

    :param settings: The settings dict to validate.
    :return: The validated dict.
    """
    return schema.validate(settings)


def migrate(settings: dict) -> dict:
    """
    Migration of the settings ``settings`` to version V3.4.0 settings

    :param settings: The settings dict to migrate
    :return: The migrated dict
    """

    # rename keys and update their value
    # add missing keys
    # TODO add new keys from mongodb.conf and modules.conf
    # name - value pairs

    # TODO drop all keys with a default value from the dictionary
    # TODO delete .conf files after migration

    if not validate(settings):
        raise SchemaError("V3.4.0: Schema error while validating")
    return normalize(settings)
