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

import os.path

from fw_config import OLD_CONFIG, CONFIG
from fw_parser import parseSysconfigArgs
import fw_compat
import shutil

def read_sysconfig_args():
    filename = None
    if os.path.exists(CONFIG) and os.path.isfile(CONFIG):
        filename = CONFIG
    elif os.path.exists(OLD_CONFIG) and os.path.isfile(OLD_CONFIG):
        filename = OLD_CONFIG
    try:
        fd = open(filename, 'r')
    except:
        return None
    argv = [ ]
    for line in fd.xreadlines():
        if not line:
            break
        line = line.strip()
        if len(line) < 1 or line[0] == '#':
            continue
        argv.append(line)
    fd.close()
    return (argv, filename)

def parse_sysconfig_args(args, merge_config=None, compat=False, filename=None):
    config = parseSysconfigArgs(args, options=merge_config, compat=compat,
                                source=filename)
    if not config:
        return None
    config.filename = filename
    if config.filename == OLD_CONFIG:
        fw_compat.convertToServices(config)
        config.converted = True
    return config

def read_sysconfig_config(merge_config=None, compat=False):
    args = read_sysconfig_args() # returns: (args, filename) or None
    if not args:
        return merge_config
    return parse_sysconfig_args(args[0], merge_config, compat, args[1])

def write_sysconfig_config(filename, conf):
    if os.path.exists(filename):
        try:
            shutil.copy2(filename, "%s.old" % filename)
        except:
            return False

    try:
        fd = open(filename, 'w')
    except:
        return False

    os.chmod(filename, 0600)
    fd.write("# Configuration file for system-config-firewall\n")
    fd.write("\n")

    if conf.enabled == True:
        fd.write("--enabled\n")
    elif conf.enabled == False:
        fd.write("--disabled\n")

    if conf.trust:
        for dev in conf.trust:
            fd.write("--trust=%s\n" % dev)
    if conf.masq:
        for dev in conf.masq:
            fd.write("--masq=%s\n" % dev)

    if conf.ports and len(conf.ports) > 0:
        for (ports, proto) in conf.ports:
            fd.write("--port=%s:%s\n" % ('-'.join(map(str, ports)), proto))

    if conf.custom_rules and len(conf.custom_rules) > 0:
            for custom in conf.custom_rules:
                fd.write("--custom-rules=%s\n" % ":".join(custom))

    if conf.services:
        for service in conf.services:
            fd.write("--service=%s\n" % service)

    if conf.block_icmp:
        for icmp in conf.block_icmp:
            fd.write("--block-icmp=%s\n" % icmp)

    if conf.forward_port:
        for fwd in conf.forward_port:
            if len(fwd["port"]) == 1:
                port = "%s" % fwd["port"][0]
            else:
                port = "%s-%s" % (fwd["port"][0], fwd["port"][1])
            line = "if=%s:port=%s:proto=%s" % (fwd["if"], port, fwd["proto"])
            if fwd.has_key("toport"):
                if len(fwd["toport"]) == 1:
                    line += ":toport=%s" % fwd["toport"][0]
                else:
                    line += ":toport=%s-%s" % (fwd["toport"][0],
                                               fwd["toport"][1])
            if fwd.has_key("toaddr"):
                line += ":toaddr=%s" % fwd["toaddr"]
            fd.write("--forward-port=%s\n" % line)

    fd.close()
    return True
