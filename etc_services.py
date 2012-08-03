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

ETC_SERVICES = "/etc/services"

def isNumber(string):
    try:
        i = int(string)
    except ValueError:
        return 0
    else:
        return 1

class _Service:
    def __init__(self):
        self.clear()
    def clear(self):
        self.p_id = 0
        self.p_protocol = ""
        self.p_name = ""
        self.p_description = ""
        self.p_aliases = [ ]
    def setID(self, id):
        self.p_id = id
    def getId(self):
        return self.p_id
    def setProtocol(self, protocol):
        self.p_protocol = protocol
    def getProtocol(self):
        return self.p_protocol
    def setName(self, name):
        self.p_name = name
    def getName(self):
        return self.p_name
    def setDescription(self, description):
        self.p_description = description
    def getDescription(self):
        return self.p_description
    def setAliases(self, aliases):
        self.p_aliases = aliases
    def getAliases(self):
        return self.p_aliases
    def __str__(self):
        s = "%s\t%d/%s" % (self.getName(), self.getId(), self.getProtocol())
        if len(self.getAliases()) > 0:
            s += "\t%s" % " ".join(self.getAliases())
        if self.getDescription() != "":
            s += "\t# %s" % self.getDescription()
        return s
    __repr__ = __str__

class _Services(list):
    def __init__(self):
        list.__init__(self)
        self.load()

    def load(self):
        try:
            fd = open(ETC_SERVICES, "r")
        except Exception, msg:
            print msg
            return
        for line in fd.xreadlines():
            if not line: break
            if len(line) < 1 or line[0] == '#':
                continue
            line = line.strip()
            # remove all after '#'
            p = line.split("#")
            if len(p) < 1:
                continue
            line = p[0]
            if len(p) > 1:
                description = p[1].strip()
            else:
                description = None

            # remove empty lines
            if len(line) < 1: continue
            # remove entries without service name and port/protocol
            p = line.split()
            if len(p) < 2:
                continue
            # new service
            service = _Service()
            # set name and description
            service.setName(p[0])
            if description != None:
                service.setDescription(description)
            # port and protocol?
            p2 = p[1].split("/")
            if len(p2) < 2:
                continue
            # convert to port id
            try:
                id = int(p2[0])
            except ValueError:
                continue
            else:
                service.setID(id)
            # set protocol
            service.setProtocol(p2[1])
            # append aliases
            service.setAliases(p[2:])

            # append service
            self.append(service)

        fd.close()    

services = _Services()
