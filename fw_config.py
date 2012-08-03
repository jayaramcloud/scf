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

# translation
import locale
locale.setlocale(locale.LC_ALL, "")

DOMAIN = 'system-config-firewall'
import gettext
_ = lambda x: gettext.ldgettext(DOMAIN, x)
import __builtin__
__builtin__.__dict__['_'] = _

# global ui reference for parser
ui = None

# configuration
APP_NAME = 'system-config-firewall'
DATADIR = '/usr/share/' + APP_NAME
GLADE_NAME = APP_NAME + '.glade'
COPYRIGHT = '(C) 2007-2009 Red Hat, Inc.'
VERSION = '1.2.27'
AUTHORS = [
    "Thomas Woerner <twoerner@redhat.com>",
    "Chris Lumens <clumens@redhat.com>",
    "Florian Festi <ffesti@redhat.com>",
    "Brent Fox <bfox@redhat.com>",
    ]
LICENSE = _(
    "This program is free software; you can redistribute it and/or modify "
    "it under the terms of the GNU General Public License as published by "
    "the Free Software Foundation; either version 2 of the License, or "
    "(at your option) any later version.\n"
    "\n"
    "This program is distributed in the hope that it will be useful, "
    "but WITHOUT ANY WARRANTY; without even the implied warranty of "
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
    "GNU General Public License for more details.\n"
    "\n"
    "You should have received a copy of the GNU General Public License "
    "along with this program.  If not, see <http://www.gnu.org/licenses/>.")

IP4TABLES_RULES = '/etc/sysconfig/iptables'
IP6TABLES_RULES = '/etc/sysconfig/ip6tables'
IP4TABLES_CFG = '/etc/sysconfig/iptables-config'
IP6TABLES_CFG = '/etc/sysconfig/ip6tables-config'

CONFIG = '/etc/sysconfig/system-config-firewall'
OLD_CONFIG = '/etc/sysconfig/system-config-securitylevel'

SE_CONFIG = '/etc/selinux/config'
OLD_SE_CONFIG = '/etc/sysconfig/selinux'

SYSCTL_CONFIG = '/etc/sysctl.conf'

STD_DEVICES = [ "eth", "ppp", "isdn", "ippp", "tun", "wlan" ]
FIREWALL_TYPES = [ "ipv4", "ipv6" ]
FIREWALL_TABLES = [ "mangle", "nat", "filter" ]

DEFAULT_TYPES = [ "server", "desktop" ]

SELINUX_MODES = [ "enforcing", "permissive", "disabled" ]
DEFAULT_SELINUX_MODE = "enforcing"
DEFAULT_SELINUX_TYPE = "targeted"
