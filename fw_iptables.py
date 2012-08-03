#
# Copyright (C) 2007, 2008 Red Hat, Inc.
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

import os, os.path
import tempfile
import shutil
import types
import fw_services
import fw_icmp

from fw_config import _
from fw_functions import *

##############################################################################

class _Setting:
    def __init__ (self, key, name, description=None, iptables=False,
                  ip6tables=False): 
        self.key = key
        self.name = name
        self.description = description
        self.iptables = iptables
        self.ip6tables = ip6tables

setting_list = [
    _Setting("MODULES_UNLOAD", _("Unload modules on restart and stop"),
             _("To ensure a sane state, the kernel firewall modules must be "
               "unloaded when the firewall is restarted or stopped."),
             True, True),
    _Setting("SAVE_ON_STOP", _("Save on stop"),
             _("Save the active firewall configuration with all changes since "
               "the last start before stopping the firewall. Only do this if "
               "you need to preserve the active state for the next start.")),
    _Setting("SAVE_ON_RESTART", _("Save on restart"),
             _("Save the active firewall configuration with all changes since "
               "the last start before restarting the firewall. Only do this if "
               "you need to preserve the active state for the next start.")),
    _Setting("SAVE_COUNTER", _("Save and restore counter"),
             _("<i>Save on stop</i> and <i>Save on restart</i> additionally "
               "save rule and chain counter.")),
    _Setting("STATUS_NUMERIC", _("Numeric status output"),
             _("Print addresses and ports in numeric format for the status "
               "output."),
             True, True),
    _Setting("STATUS_VERBOSE", _("Verbose status"),
             _("Print information about the number of packets and bytes plus "
               "the <i>input-</i> and <i>outputdevice</i> in the status "
               "output.")),
    _Setting("STATUS_LINENUMBERS", _("Status line numbers"),
             _("Print a counter/number for every rule in the status output."),
             True, True),
    ]

def getByKey(key):
    for x in setting_list:
        if x.key == key:
            return x
    return None

def getByName(name):
    for x in setting_list:
        if x.name == name:
            return x
    return None

##############################################################################

class ip4tablesConfig:
    prefix = "IPTABLES_"

    def __init__(self, filename):
        self.filename = filename
        self.clear()

    def clear(self):
        self.p_config = { }
        self.set("%sMODULES" % self.prefix, [ ])
        self.set("%sMODULES_UNLOAD" % self.prefix, "yes")
        self.set("%sSAVE_ON_STOP" % self.prefix, "no")
        self.set("%sSAVE_ON_RESTART" % self.prefix, "no")
        self.set("%sSAVE_COUNTER" % self.prefix, "no")
        self.set("%sSTATUS_NUMERIC" % self.prefix, "yes")
        self.set("%sSTATUS_VERBOSE" % self.prefix, "no")
        self.set("%sSTATUS_LINENUMBERS" % self.prefix, "yes")

    def get(self, key):
        if key in self.p_config.keys():
            return self.p_config[key]
        return None

    def set(self, key, value):
        if key[-8:] == "_MODULES":
            self.p_config[key.strip()] = value
        else:
            self.p_config[key.strip()] = value.strip()

    def __str__(self):
        s = ""
        for (key,value) in self.p_config.items():
            if s:
                s += '\n'
            s += '%s = %s' % (key, value)
        return s

    # load self.filename
    def read(self):
        self.clear()
        file = open(self.filename, "r")
        for line in file.xreadlines():
            if not line:
                break
            line = line.strip()
            if len(line) < 1 or line[0] == '#':
                continue
            # get key/value pairs
            p = line.split("=")
            if len(p) != 2:
                continue
            key = p[0].strip()
            value = p[1].strip()
            # remove leading and trailing double quotes
            if len(value) > 0 and value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            if key[-8:] == "_MODULES":
                value = value.split()
            self.p_config[key] = value
        file.close()

    # save to self.filename if there are key/value changes
    def write(self):
        if len(self.p_config) < 1:
            # no changes: nothing to do
            return

        if os.path.exists(self.filename):
            shutil.copy2(self.filename, "%s.old" % self.filename)

        temp_dir = tempfile.mkdtemp()
        temp_file = "%s/%s" % (temp_dir, "config")
        fd = open(temp_file, "w")

        modified = False
        try:
            file = open(self.filename, "r")
        except:
            file = None
        else:
            for line in file.xreadlines():
                if not line: break
                # remove newline at and on line
                if line[-1:] == "\n":
                    line = line[:-1]
                if len(line) < 1:
                    fd.write("\n")
                    continue

                if line[0] != "#" and len(line) > 1:
                    p = line.split("=")
                    if len(p) != 2:
                        fd.write(line+"\n")
                        continue
                    key = p[0].strip()
                    value = p[1].strip()
                    # remove leading and trailing double quotes
                    if len(value) > 0 and value[0] == '"' and value[-1] == '"':
                        value = value[1:-1]
                    if key[-8:] == "_MODULES":
                        value = value.split()
                    if (key in self.p_config.keys() and \
                            self.p_config[key] != value) or \
                            key not in self.p_config.keys():
                        self._write(fd, key, self.p_config[key])
                        modified = True
                        del self.p_config[key]
                    else:
                        fd.write(line+"\n")
                        del self.p_config[key]
                else:
                    fd.write(line+"\n")
        # write remaining key/value pairs
        if len(self.p_config) > 0:
            fd.write("\n")
        for (key,value) in self.p_config.items():
            self._write(fd, key, value)
            modified = True

        if file:
            file.close()
        fd.close()

        try:
            file = open(self.filename, "w")
        except:
            shutil.rmtree(temp_dir)
            raise IOError, "Permission denied: '%s'" % self.filename
        os.chmod(self.filename, 0600)

        # copy content
        for line in open(temp_file, "r"):
            file.write(line)
        file.close()

        shutil.rmtree(temp_dir)

    def _write(self, fd, key, value):
        if isinstance(value, types.ListType) or \
               isinstance(value, types.TupleType):
            val = " ".join(value)
        else:
            val = value
        fd.write('%s="%s"\n' % (key, val))

##############################################################################

class ip6tablesConfig(ip4tablesConfig):
    prefix = "IP6TABLES_"

##############################################################################

class iptablesClass:
    prog = "iptables"
    type = "ipv4"

    def __init__(self, filename):
        self.filename = filename

    def write(self, conf):
        if self.type == "ipv4":
            reject_type = "icmp-host-prohibited"
        else:
            reject_type = "icmp6-adm-prohibited"

        custom_mangle = [ ]
        custom_nat = [ ]
        custom_filter = [ ]
        if conf.custom_rules and len(conf.custom_rules) > 0:
            for (_type, table, filename) in conf.custom_rules:
                if _type != self.type:
                    continue
                # ignore missing files
                if not os.path.exists(filename) or \
                       not os.path.isfile(filename):
                    continue
                if table == "mangle":
                    custom_mangle.append(filename)
                elif table == "nat":
                    custom_nat.append(filename)
                elif table == "filter":
                    custom_filter.append(filename)

        if os.path.exists(self.filename):
            shutil.copy2(self.filename, "%s.old" % self.filename)

        # do we have local or remote forwarding?
        local_forward = False
        remote_forward = False
        if conf.forward_port:
            for fwd in conf.forward_port:
                if fwd.has_key("toaddr"):
                    remote_forward = True
                else:
                    local_forward = True

        mark_idx = 100

        fd = open(self.filename, "w")
        os.chmod(self.filename, 0600)

        fd.write("# Firewall configuration written by system-config-firewall\n")
        fd.write("# Manual customization of this file is not recommended.\n")

        ### MANGLE ###

        if len(custom_mangle) > 0 or (self.type == "ipv4" and local_forward):
            fd.write("*mangle\n")
            fd.write(":PREROUTING ACCEPT [0:0]\n")
            fd.write(":INPUT ACCEPT [0:0]\n")
            fd.write(":FORWARD ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":POSTROUTING ACCEPT [0:0]\n")
            # custom rules
            for filename in custom_mangle:
                catFile(fd, filename)
            if self.type == "ipv4" and \
                    (conf.forward_port and len(conf.forward_port) > 0):
                for fwd in conf.forward_port:
                    if fwd.has_key("toaddr"):
                        continue
                    port = self._portStr(fwd["port"])
                    fwd["mark"] = mark_idx
                    mark_idx += 1
                    fd.write("-A PREROUTING -i %s -p %s --dport %s "
                             "-j MARK --set-mark 0x%x\n" % (fwd["if"],
                                                            fwd["proto"],
                                                            port,
                                                            fwd["mark"]))

            fd.write("COMMIT\n")

        ### NAT ###

        # no support for nat for netfilterv6 for now
        if self.type == "ipv4" and \
                ((conf.masq and len(conf.masq) > 0) or len(custom_nat) > 0 or \
                 (conf.forward_port and len(conf.forward_port) > 0)):
            fd.write("*nat\n")
            fd.write(":PREROUTING ACCEPT [0:0]\n")
            fd.write(":OUTPUT ACCEPT [0:0]\n")
            fd.write(":POSTROUTING ACCEPT [0:0]\n")
            # masquerading
            if conf.masq:
                for dev in conf.masq:
                    fd.write("-A POSTROUTING -o %s -j MASQUERADE\n" % dev)
            # port forward
            if conf.forward_port:
                for fwd in conf.forward_port:
                    port = self._portStr(fwd["port"])
                    to = ""
                    mark = ""
                    if fwd.has_key("toaddr"):
                        to += fwd["toaddr"]
                    else:
                        mark = "-m mark --mark 0x%x " % fwd["mark"]

                    if fwd.has_key("toport"):
                        # the port range delimiter for DNAT is '-'
                        to += ":%s" % self._portStr(fwd["toport"], "-")

                    fd.write("-A PREROUTING -i %s -p %s --dport %s %s"
                             "-j DNAT --to-destination %s\n" % \
                                 (fwd["if"], fwd["proto"], port, mark, to))

            # custom rules
            for filename in custom_nat:
                catFile(fd, filename)
            fd.write("COMMIT\n")

        ### FILTER ###

        fd.write("*filter\n")
        fd.write(":INPUT ACCEPT [0:0]\n")
        fd.write(":FORWARD ACCEPT [0:0]\n")
        fd.write(":OUTPUT ACCEPT [0:0]\n")

        # INPUT

        # accept established and related connections as early as possible
        #   RELATED is extremely important as it matches ICMP error messages
        fd.write("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")

        # icmp
        self._icmp(conf, fd, "INPUT", reject_type)
        # trust lo
        fd.write("-A INPUT -i lo -j ACCEPT\n")
        # trusted interfaces
        if conf.trust:
            for dev in conf.trust:
                fd.write("-A INPUT -i %s -j ACCEPT\n" % dev)
        # forward local
        if self.type == "ipv4" and conf.forward_port:
            for fwd in conf.forward_port:
                if fwd.has_key("toaddr"):
                    continue
                line = "-A INPUT -i %s -m state --state NEW -m %s -p %s" % \
                    (fwd["if"], fwd["proto"], fwd["proto"])
                if fwd.has_key("toport"):
                    line += " --dport %s" % self._portStr(fwd["toport"])
                line += " -m mark --mark 0x%x" % fwd["mark"]
                line += " -j ACCEPT\n"
                fd.write(line)

        # open services
        if conf.services and len(conf.services) > 0:
            for service in conf.services:
                svc = fw_services.getByKey(service)
                for (port,proto) in svc.ports:
                    _state = ""
                    _dest = ""
                    _port = ""
                    if proto in [ "tcp", "udp" ]:
                        _state = "-m state --state NEW "
                        _proto = "-m %s -p %s " % (proto, proto)
                    else:
                        if self.type == "ipv4":
                            _proto = "-p %s " % proto
                        else:
                            _proto = "-m ipv6header --header %s " % proto
                    if port:
                        _port = "--dport %s " % port
                    if svc.destination.has_key(self.type):
                        _dest = "-d %s " % svc.destination[self.type]
                    fd.write("-A INPUT " + _state + _proto + _port + _dest + 
                             "-j ACCEPT\n")

        # open ports
        if conf.ports and len(conf.ports) > 0:
            for (ports, proto) in conf.ports:
                fd.write("-A INPUT -m state --state NEW -m %s -p %s --dport %s "
                         "-j ACCEPT\n" % (proto, proto, self._portStr(ports)))

        # FORWARD
        if (conf.trust and len(conf.trust) > 0) or \
                (self.type == "ipv4" and conf.masq and len(conf.masq) > 0) or \
                (self.type == "ipv4" and remote_forward):
            # accept established and related connections
            fd.write("-A FORWARD -m state --state ESTABLISHED,RELATED "
                     "-j ACCEPT\n")
            # icmp
            self._icmp(conf, fd, "FORWARD", reject_type)
            # trust lo
            fd.write("-A FORWARD -i lo -j ACCEPT\n")
            # trusted interfaces
            if conf.trust:
                for dev in conf.trust:
                    fd.write("-A FORWARD -i %s -j ACCEPT\n" % dev)
            # allow to output to masqueraded interfaces (IPv4 only)
            if self.type == "ipv4" and conf.masq:
                for dev in conf.masq:
                    fd.write("-A FORWARD -o %s -j ACCEPT\n" % dev)
            # forward remote
            if self.type == "ipv4" and conf.forward_port and remote_forward:
                for fwd in conf.forward_port:
                    if not fwd.has_key("toaddr"):
                        continue
                    if fwd.has_key("toport"):
                        port = self._portStr(fwd["toport"])
                    else:
                        port = self._portStr(fwd["port"])
                    fd.write("-A FORWARD -i %s -m state --state NEW "
                             "-m %s -p %s -d %s --dport %s "
                             "-j ACCEPT\n" % (fwd["if"], fwd["proto"],
                                              fwd["proto"], fwd["toaddr"],
                                              port))
        # add custom filter rules
        if len(custom_filter) > 0:
            for _filename in custom_filter:
                catFile(fd, _filename)

        # reject remaining INPUT and OUTPUT
        fd.write("-A INPUT -j REJECT --reject-with %s\n" % reject_type)
        fd.write("-A FORWARD -j REJECT --reject-with %s\n" % reject_type)

        # OUTPUT
        # no output rules, yet
        fd.write("COMMIT\n")
        fd.close()

    def _icmp(self, conf, fd, chain, reject_type):
        if self.type == "ipv4":
            proto = "-p icmp"
            match = "-m icmp --icmp-type"
        else:
            proto = "-p ipv6-icmp"
            match = "-m icmp6 --icmpv6-type"

        for key in conf.block_icmp:
            icmp = fw_icmp.getByKey(key)
            if icmp.type and self.type not in icmp.type:
                continue
            fd.write("-A %s %s %s %s -j REJECT --reject-with %s\n" % \
                         (chain, proto, match, key, reject_type))
        fd.write("-A %s %s -j ACCEPT\n" % (chain, proto))

    def _portStr(self, port, delimiter=":"):
        if len(port) == 1:
            return "%s" % port
        else:
            return "%s%s%s" % (port[0], delimiter, port[1])

    def _run(self, prog, arg, verbose=False):
        cmd = "%s %s %s" % (prog, self.prog, arg)
        if not verbose:
            cmd += " >/dev/null 2>&1"
        return os.system(cmd) >> 8

    def start(self, verbose=False):
        return self._run("/sbin/service", "start", verbose)

    def restart(self, verbose=False):
        return self._run("/sbin/service", "restart", verbose)

    def condrestart(self, verbose=False):
        return self._run("/sbin/service", "condrestart", verbose)

    def status(self, verbose=False):
        return self._run("/sbin/service", "status", verbose)

    def stop(self, verbose=False):
        return self._run("/sbin/service", "stop", verbose)

    def chkconfig_on(self, verbose=False):
        return self._run("/sbin/chkconfig", "on", verbose)

    def chkconfig_off(self, verbose=False):
        return self._run("/sbin/chkconfig", "off", verbose)

    def unlink(self):
        if os.path.exists(self.filename) and os.path.isfile(self.filename):
            os.unlink(self.filename)

##############################################################################

class ip6tablesClass(iptablesClass):
    prog = "ip6tables"
    type = "ipv6"
