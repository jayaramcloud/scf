#
# Copyright (C) 2009 Red Hat, Inc.
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

import gobject
import dbus
import dbus.service
import dbus.mainloop.glib
import slip.dbus
import slip.dbus.service
import json

import fw_sysconfig
import fw_lokkit

#

DBUS_DOMAIN = "org.fedoraproject.Config.Firewall"
DBUS_PATH = "/org/fedoraproject/Config/Firewall"
POLKIT_DOMAIN = "org.fedoraproject.config.firewall"

#

class DBusProxy(object):
    def __init__(self):
        try:
            self.bus = slip.dbus.SystemBus()
            self.bus.default_timeout = None
        except:
            self.bus = dbus.SystemBus()
        self.dbus_obj = self.bus.get_object(DBUS_DOMAIN, DBUS_PATH)

    @slip.dbus.polkit.enable_proxy
    def auth(self):
        return self.dbus_obj.auth(dbus_interface=DBUS_DOMAIN)

    @slip.dbus.polkit.enable_proxy
    def read(self):
        rep = self.dbus_obj.read(dbus_interface=DBUS_DOMAIN)
        try:
            args = json.loads(rep.encode('utf-8'))
        except:
            return None
        return args

    @slip.dbus.polkit.enable_proxy
    def write(self, args):
        try:
            rep = json.dumps(args)
        except:
            return -1
        return self.dbus_obj.write(rep.encode('utf-8'),
                                   dbus_interface=DBUS_DOMAIN)

#

class DBusService(slip.dbus.service.Object):
    # create service object
    def __init__(self, *p, **k):
        super(DBusService, self).__init__(*p, **k)
        self.persistent = True

    # delete service object
    def __del__(self):
        pass

    @slip.dbus.polkit.require_auth("%s.auth" % POLKIT_DOMAIN)
    @dbus.service.method(DBUS_DOMAIN, in_signature='', out_signature='i')
    def auth(self):
        return 1

    # read args
#    @slip.dbus.polkit.require_auth("%s.read" % POLKIT_DOMAIN)
    @slip.dbus.polkit.require_auth("%s.auth" % POLKIT_DOMAIN)
    @dbus.service.method(DBUS_DOMAIN, in_signature='', out_signature='s')
    def read(self):
        args = fw_sysconfig.read_sysconfig_args()
        try:
            rep = json.dumps(args)
        except:
            return None
        return rep.encode('utf-8')    

    # write args
#    @slip.dbus.polkit.require_auth("%s.write" % POLKIT_DOMAIN)
    @slip.dbus.polkit.require_auth("%s.auth" % POLKIT_DOMAIN)
    @dbus.service.method(DBUS_DOMAIN, in_signature='s', out_signature='i')
    def write(self, rep):
        try:
            args = json.loads(rep.encode('utf-8'))
        except:
            return -1

        (config, old_config, \
             old_se_config) = fw_lokkit.loadConfig(args, dbus_parser=1)
        se_status = fw_lokkit.updateSELinux(config, old_se_config)
        (c_status, ip4t_status, \
             ip6t_status, log) = fw_lokkit.updateFirewall(config, old_config)

        return (ip4t_status + ip6t_status + c_status + se_status)

#

def run_service():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    name = dbus.service.BusName(DBUS_DOMAIN, bus)
    service = DBusService(name, DBUS_PATH)

    mainloop = gobject.MainLoop()
    slip.dbus.service.set_mainloop(mainloop)
    mainloop.run()
