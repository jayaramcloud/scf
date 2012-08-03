#
# Copyright (C) 2007 Red Hat, Inc.
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

from fw_config import OLD_SE_CONFIG, SE_CONFIG

##############################################################################

def read():
    filename = None
    if os.path.exists(SE_CONFIG) and os.path.isfile(SE_CONFIG):
        filename = SE_CONFIG
    elif os.path.exists(OLD_SE_CONFIG) and os.path.isfile(OLD_SE_CONFIG):
        filename = OLD_SE_CONFIG
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
        p = line.split("=")
        if len(p) != 2:
            continue
        key = p[0].strip()
        value = p[1].strip()
        if key == "SELINUX":
            argv.append("--selinux=%s" % value)
        elif key == "SELINUXTYPE":
            argv.append("--selinuxtype=%s" % value)
    fd.close()
    return argv

def write(conf, filename=SE_CONFIG):
    try:
        fd = open(filename, "w")
    except:
        return False
    fd.write("# This file controls the state of SELinux on the system.\n")
    fd.write("# SELINUX= can take one of these three values:\n")
    fd.write("#\tenforcing - SELinux security policy is enforced.\n")
    fd.write("#\tpermissive - SELinux prints warnings instead of enforcing.\n")
    fd.write("#\tdisabled - SELinux is fully disabled.\n")
    fd.write("SELINUX=%s\n" % conf.selinux)
    fd.write("# SELINUXTYPE= type of policy in use. Possible values are:\n")
    fd.write("#\ttargeted - Only targeted network daemons are protected.\n")
    fd.write("#\tstrict - Full SELinux protection.\n")
    if conf.selinuxtype:
        fd.write("SELINUXTYPE=%s\n" % conf.selinuxtype)
    else:
        fd.write("#SELINUXTYPE=\n")
    fd.close()
    return True

def setenforce(value):
    val = 0 # permissive, disabled
    if value == "enforcing":
        val = 1
    return os.system("/usr/sbin/setenforce %d" % val)
