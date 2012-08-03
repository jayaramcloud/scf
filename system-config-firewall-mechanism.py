#!/usr/bin/python
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

import sys
DATADIR = '/root/scf'
sys.path.append(DATADIR)

import fw_dbus
import syslog, traceback

try:
    fw_dbus.run_service()
except Exception, msg:
    syslog.syslog(syslog.LOG_ERR, "%s: ERROR: %s" % (sys.argv[0], msg))
    print traceback.format_exc()
    sys.exit(1)

sys.exit(0)
