"""
configgen.py: Generate configuration data.

module for generating configuration manifest using autoinstall_meta data, mgmtclasses, resources, and templates for a
given system (hostname)
"""

# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Copyright 2010 Kelsey Hightower <kelsey.hightower@gmail.com>

import json
import string
from typing import TYPE_CHECKING, Any, Dict, List, Set, Union

from cobbler import template_api, utils
from cobbler.cexceptions import CX

if TYPE_CHECKING:
    from cobbler.api import CobblerAPI
    from cobbler.enums import ResourceAction

# FIXME: This is currently getting the blendered data. Make use of the object and only process the required data.
# FIXME: Obsolete this class. All methods are wrappers or tailcalls except gen_config_data and this can be integrated
#        somewhere else (educated guess: System or Koan directly).


class ConfigGen:
    """
    Generate configuration data for Cobbler's management resources: repos, files and packages.
    Mainly used by Koan to configure systems.
    """

    def __init__(self, cobbler_api: "CobblerAPI", hostname: str):
        """
        Constructor. Requires a Cobbler API handle.

        :param hostname: The hostname to run config-generation for.
        """
        # FIXME: This should work via the system name or system record and if that doesn't exist it should not fail.
        self.hostname = hostname
        self.__api = cobbler_api
        target_system = self.__api.find_system(hostname=self.hostname)
        if target_system is None or isinstance(target_system, list):
            raise ValueError("The specified hostname did not exist or was ambigous!")
        self.system = target_system
        # This below var needs a dict but the method may possibly return an empty str.
        self.host_vars = self.get_cobbler_resource("autoinstall_meta")
        self.mgmtclasses = self.get_cobbler_resource("mgmt_classes")

    # ----------------------------------------------------------------------

    def resolve_resource_var(self, string_data: Union["ResourceAction", str]) -> str:
        """
        Substitute variables in strings with data from the ``autoinstall_meta`` dictionary of the system.

        :param string_data: The template which will then be substituted by the variables in this class.
        :return: A str with the substituted data. If the host_vars are not of type dict then this will return an empty
                 str.
        :raises KeyError: When the autoinstall_meta variable does not contain the required Keys in the dict.
        """
        if not isinstance(self.host_vars, dict):
            return ""
        return string.Template(str(string_data)).substitute(self.host_vars)

    # ----------------------------------------------------------------------

    def get_cobbler_resource(
        self, resource_key: str
    ) -> Union[List[Any], str, Dict[Any, Any]]:
        """
        Wrapper around Cobbler blender method

        :param resource_key: Not known what this actually is doing.
        :return: The blendered data. In some cases this is a str, in others it is a list or it might be a dict. In case
                 the key is not found it will return an empty string.
        """
        system_resource = utils.blender(self.__api, False, self.system)
        if resource_key not in system_resource:
            return ""
        return system_resource[resource_key]

    # ----------------------------------------------------------------------

    def gen_config_data(self) -> Dict[Any, Any]:
        """
        Generate configuration data for repos, files and packages.

        :return: A dict which has all config data in it.
        :raises CX: In case the package or file resource is not defined.
        """
        config_data = {
            "repo_data": self.__api.get_repo_config_for_system(self.system),
            "repos_enabled": self.get_cobbler_resource("repos_enabled"),
        }
        package_set: Set[str] = set()
        file_set: Set[str] = set()

        for mgmtclass in self.mgmtclasses:
            _mgmtclass = self.__api.find_mgmtclass(name=mgmtclass)
            if _mgmtclass is None or isinstance(_mgmtclass, list):
                raise ValueError("Ambigous or no search result!")
            for package in _mgmtclass.packages:
                package_set.add(package)
            for file in _mgmtclass.files:
                file_set.add(file)

        # Generate Package data
        pkg_data: Dict[str, Dict[str, str]] = {}
        for package in package_set:
            _package = self.__api.find_package(name=package)
            if _package is None or isinstance(_package, list):
                raise CX(f"{package} package resource is not defined")
            pkg_data[package] = {}
            pkg_data[package]["action"] = self.resolve_resource_var(_package.action)
            pkg_data[package]["installer"] = _package.installer
            pkg_data[package]["version"] = self.resolve_resource_var(_package.version)
            if pkg_data[package]["version"] != "":
                pkg_data[package][
                    "install_name"
                ] = f"{package}-{pkg_data[package]['version']}"
            else:
                pkg_data[package]["install_name"] = package
        config_data["packages"] = pkg_data

        # Generate File data
        file_data: Dict[str, Dict[str, Union[str, bool]]] = {}
        for file in file_set:
            _file = self.__api.find_file(name=file)

            if _file is None or isinstance(_file, list):
                raise CX(f"{file} file resource is not defined")

            file_data[file] = {}
            file_data[file]["is_dir"] = _file.is_dir
            file_data[file]["action"] = self.resolve_resource_var(_file.action)
            file_data[file]["group"] = self.resolve_resource_var(_file.group)
            file_data[file]["mode"] = self.resolve_resource_var(_file.mode)
            file_data[file]["owner"] = self.resolve_resource_var(_file.owner)
            file_data[file]["path"] = self.resolve_resource_var(_file.path)

            if not _file.is_dir:
                file_data[file]["template"] = self.resolve_resource_var(_file.template)
                try:
                    template_api_instance = template_api.CobblerTemplate(
                        file=file_data[file]["template"], searchList=[self.host_vars]
                    )
                    file_data[file]["content"] = template_api_instance.respond()  # type: ignore
                except Exception as exception:
                    raise ValueError(
                        f"Missing template for this file resource {file_data[file]}"
                    ) from exception

        config_data["files"] = file_data
        return config_data

    # ----------------------------------------------------------------------

    def gen_config_data_for_koan(self) -> str:
        """
        Encode configuration data. Return json object for Koan.

        :return: A json string for koan.
        """
        # TODO: This can be merged with the above method if we want to obsolete this class. If not, we need to create
        #       helper objects instead of just having a nested dictionary.
        json_config_data = json.JSONEncoder(sort_keys=True, indent=4).encode(
            self.gen_config_data()
        )
        return json_config_data
