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

import socket, types

def getPortID(port):
    if isinstance(port, types.IntType):
        id = port
    else:
        if port:
            port = port.strip()
        try:
            id = int(port)
        except:
            try:
                id = socket.getservbyname(port)
            except:
                return -1
    if id > 65535:
        return -1
    return id

def getPortRange(ports):
    if isinstance(ports, types.IntType):
        id = getPortID(ports)
        if id >= 0:
            return (id,)
        return -1

    splits = ports.split("-")
    matched = [ ]
    for i in xrange(len(splits), 0, -1):
        id1 = getPortID("-".join(splits[:i]))
        port2 = "-".join(splits[i:])
        if len(port2) > 0:
            id2 = getPortID(port2)
            if id1 >= 0 and id2 >= 0:
                if id1 < id2:
                    matched.append((id1, id2))
                elif id1 > id2:
                    matched.append((id2, id1))
                else:
                    matched.append((id1, ))
        else:
            if id1 >= 0:
                matched.append((id1,))
                if i == len(splits):
                    # full match, stop here
                    break
    if len(matched) < 1:
        return -1
    elif len(matched) > 1:
        return None
    return matched[0]

def getServiceName(port, proto):
    try:
        name = socket.getservbyport(int(port), proto)
    except:
        return None
    return name

def catFile(fd, filename):
    try:
        source_fd = open(filename, "r")
    except:
        return False
    for line in source_fd.xreadlines():
        fd.write(line)
    source_fd.close()
    return True

def checkIP(ip):
    if ip != "":
        splits = ip.split(".")
        if len(splits) != 4:
            return False
        for i in xrange(len(splits)):
            try:
                l = int(splits[i])
            except:
                return False
            if l < 0 or l > 255:
                return False
    return True

def checkInterface(iface):
    if not iface or len(iface) > 16:
        return False
    for ch in [ ' ', '/', '!', ':', '*' ]:
        # !:* are limits for iptables <= 1.4.5
        if ch in iface:
            return False
    if iface == "+":
        # limit for iptables <= 1.4.5
        return False
    return True
