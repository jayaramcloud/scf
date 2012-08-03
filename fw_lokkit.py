#
# Copyright (C) 2007-2009 Red Hat, Inc.
# Authors:
# Thomas Woerner <twoerner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import fw_config
from fw_parser import parseLokkitArgs, parseDBUSArgs, parseSysconfigArgs, \
    parseSELinuxArgs, copyValues
from fw_iptables import *
from fw_sysconfig import *
from fw_sysctl import *
import fw_selinux
import fw_services
import fw_icmp

### parse command line arguments ###

def loadConfig(args=None, dbus_parser=False):
    if dbus_parser:
        _parseArgs = parseDBUSArgs
    else:
        _parseArgs = parseLokkitArgs

    config = _parseArgs(args)

    # load default configuration
    if config.default:
        config.force = True

    # no force mode in update
    elif config.update:
        config.force = False

    old_config = None
    old_se_config = None
    # force mode: ignore old configuration
    # else: use old configuration and command line arguments
    if not config.force:
        ### load original configuration ###

        # initialize  old_config
        old_config = _parseArgs([ ])

        # parse /etc/sysconfig/system-config-firewall or
        # /etc/sysconfig/system-config-securitylevel
        old_config = read_sysconfig_config(old_config)

        # reparse lokkit args with a copy of the old configuration
        config = _parseArgs(args=args, options=copyValues(old_config))

        # parse selinux config
        old_se_config = parseSELinuxArgs(fw_selinux.read() or [ ])

    # load default configuration
    if config.default:
        # config.default in [ "server", "desktop" ]
        for svc in fw_services.service_list:
            if svc.default and config.default in svc.default:
                config.services.append(svc.key)

    # no force mode in update
    elif config.update:
        config.quiet = True
        config.nostart = False

    return (config, old_config, old_se_config)

### update selinux ###

def updateSELinux(config, old_se_config):
    se_status = 0

    # selinux
    if config.selinux or config.selinuxtype:
        if old_se_config:
            if not config.selinux:
                config.selinux = old_se_config.selinux
            if not config.selinuxtype:
                config.selinuxtype = old_se_config.selinuxtype
        if not config.selinux:
            config.selinux = fw_config.DEFAULT_SELINUX_MODE
        if not config.selinuxtype:
            config.selinuxtype = fw_config.DEFAULT_SELINUX_TYPE

        if not old_se_config or (config.selinux != old_se_config.selinux or \
                                 config.selinuxtype != old_se_config.selinuxtype):
            se_status = int(fw_selinux.write(config) == False)
            if se_status != 0:
                print _("Failed to write selinux configuration.")
            else:
                fw_selinux.setenforce(config.selinuxtype)

    return se_status

### update firewall ###

def updateFirewall(config, old_config):
    c_status = ip4t_status = ip6t_status = 0
    log = ""

    # write /etc/sysconfig/system-config-securitylevel and
    # /etc/sysconfig/system-config-firewall
    c_status = int(write_sysconfig_config(fw_config.CONFIG, config) == False)
    if c_status != 0:
        log += _("Failed to write %s.") % fw_config.CONFIG
        log += "\n"

    # load ip*tables-config only if there is something to do
    if (config.add_module and len(config.add_module) > 0) or \
           (config.remove_module and len(config.remove_module) > 0):
        # load IPv4 configuration
        ip4tables_conf = ip4tablesConfig(fw_config.IP4TABLES_CFG)
        try:
            ip4tables_conf.read()
        except:
            pass
        # load IPv6 configuration
        ip6tables_conf = ip6tablesConfig(fw_config.IP6TABLES_CFG)
        try:
            ip6tables_conf.read()
        except:
            pass

        _modules = [ ]
        _modules.append(ip4tables_conf.get("IPTABLES_MODULES"))
        _modules.append(ip6tables_conf.get("IP6TABLES_MODULES"))

        # setup modules
        for modules in _modules:
            if config.add_module:
                for module in config.add_module:
                    modalias = None
                    if module[:3] == "nf_":
                        modalias = "ip_"+module[3:]
                    if module[:3] == "ip_":
                        modalias = "nf_"+module[3:]
                    if module not in modules and modalias not in modules:
                        modules.append(module)
            if config.remove_module:
                for module in config.remove_module:
                    modalias = None
                    if module[:3] == "nf_":
                        modalias = "ip_"+module[3:]
                    if module[:3] == "ip_":
                        modalias = "nf_"+module[3:]
                    if module in modules:
                        modules.remove(module)
                    if modalias in modules:
                        modules.remove(modalias)

        # TODO: check status:
        # write IPv4 configuration
        ip4tables_conf.write()
        # write IPv6 configuration
        ip6tables_conf.write()


    # update services
    if config.enabled or (old_config and old_config.enabled) or config.force:
        ip4tables = iptablesClass(fw_config.IP4TABLES_RULES)
        ip6tables = ip6tablesClass(fw_config.IP6TABLES_RULES)

        if not config.nostart:
            # stop ip*tables
            ip4t_status = ip4tables.stop(config.verbose)
            if ip4t_status != 0:
                log += _("Failed to stop %s.") % "iptables"
                log += "\n"
            ip6t_status = ip6tables.stop(config.verbose)
            if ip6t_status != 0:
                log += _("Failed to stop %s.") % "ip6tables"
                log += "\n"

        if config.enabled:
            # set ip_forward if masquerading is in use
            if config.masq and len(config.masq) > 0:
                sysctl = sysctlClass(fw_config.SYSCTL_CONFIG)
                sysctl.read()
                if sysctl.get("net.ipv4.ip_forward") != "1":
                    sysctl.set("net.ipv4.ip_forward", "1")
                    sysctl.write()
                    sysctl.reload()

            # write new config
            ip4tables.write(config)
            ip6tables.write(config)

            if not config.nostart:
                # start ip*tables
                ip4t_status = ip4tables.start(config.verbose)
                if ip4t_status == 150:
                    # ipv4 disabled, ignore
                    ip4t_status = 0
                if ip4t_status != 0:
                    log += _("Failed to start %s.") % "iptables"
                    log += "\n"
                ip6t_status = ip6tables.start(config.verbose)
                if ip6t_status == 150:
                    # ipv6 disabled, ignore
                    ip6t_status = 0
                if ip6t_status != 0:
                    log += _("Failed to start %s.") % "ip6tables"
                    log += "\n"
        else: # old_config and old_config.enabled
            # remove configuration files
            try:
                ip4tables.unlink()
            except Exception, msg:
                ip4t_status += 1
                log += _("Failed to remove %s.") % ip4tables.filename
                log += "\n"
                if config.verbose:
                    log += msg + "\n"
            try:
                ip6tables.unlink()
            except Exception, msg:
                ip6t_status += 1
                log += _("Failed to remove %s.") % ip6tables.filename
                log += "\n"
                if config.verbose:
                    log += msg + "\n"

    return (c_status, ip4t_status, ip6t_status, log)
