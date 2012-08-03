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

from fw_functions import getPortID, getServiceName
import fw_services

def convertToServices(config):
    if len(config.services) > 0:
        return

    print _("Converting %s") % config.filename
    services = config.services
    ports = [ ]
    matched = [ ]
    for svc in fw_services.service_list:
        _matched = [ ]
        if config.ports:
            all_matched = True
            for (port, proto) in svc.ports:
                id = getPortID(port)
                name = getServiceName(port, proto)
                if ((id,), proto) in config.ports:
                    _matched.append(((id,), proto))
                elif ((port,), proto) in config.ports:
                    _matched.append(((port,), proto))
                elif ((name,), proto) in config.ports:
                    _matched.append(((name,), proto))
                else:
                    all_matched = False
        else:
            all_matched = False
        if all_matched:
            services.append(svc.key)
            matched.extend(_matched)
        del _matched
    if config.ports:
        for entry in config.ports:
            if entry in matched:
                continue
            ports.append(entry)
    del matched

    if not hasattr(config, "no_ipsec") or not config.no_ipsec:
        if not "ipsec" in services:
            services.append("ipsec")
    else:
        delattr(config, "no_ipsec")
    if not hasattr(config, "no_mdns") or not config.no_mdns:
        if not "mdns" in services:
            services.append("mdns")
    else:
        delattr(config, "no_mdns")
    if not hasattr(config, "no_ipp") or not config.no_ipp:
        if not "ipp" in services:
            services.append("ipp")
    else:
        delattr(config, "no_ipp")

    config.ports = ports
