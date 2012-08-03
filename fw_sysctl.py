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
import tempfile
import shutil

##############################################################################

class sysctlClass:
    def __init__(self, filename):
        self.filename = filename
        self.clear()

    def clear(self):
        self.p_config = { }
        self.p_deleted = [ ]

    def get(self, key):
        _key = key.strip()
        if _key in self.p_config:
            return self.p_config[_key]
        return None

    def set(self, key, value):
        _key = key.strip()
        self.p_config[_key] = value.strip()
        if _key in self.p_deleted:
            self.p_deleted.remove[_key]

    def unset(self, key):
        _key = key.strip()
        if _key in self.p_config:
            del self.p_config[_key]
        if not _key in self.p_deleted:
            self.p_deleted.append(_key)

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
            if len(line) < 1 or line[0] in ['#', ';']:
                continue
            # get key/value pairs
            p = line.split("=")
            if len(p) != 2:
                continue
            self.p_config[p[0].strip()] = p[1].strip()
        file.close()

    # save to self.filename if there are key/value changes
    def write(self):
        if len(self.p_config) < 1:
            # no changes: nothing to do
            return

        # handled keys
        done = [ ]

        (temp_file, temp) = tempfile.mkstemp("sysctl.conf")
        modified = False
        empty = False
        file = open(self.filename, "r")
        for line in file.xreadlines():
            if not line: break
            # remove newline
            line = line.strip("\n")

            if len(line) < 1:
                if not empty:
                    os.write(temp_file, "\n")
                    empty = True
            elif line[0] == '#':
                empty = False
                os.write(temp_file, line)
                os.write(temp_file, "\n")
            else:
                p = line.split("=")
                if len(p) != 2:
                    empty = False
                    os.write(temp_file, line+"\n")
                    continue
                key = p[0].strip()
                value = p[1].strip()
                # check for modified key/value pairs
                if key not in done:
                    if (key in self.p_config and \
                            self.p_config[key] != value):
                        empty = False
                        os.write(temp_file, '%s = %s\n' \
                                     % (key, self.p_config[key]))
                        modified = True
                    elif key in self.p_deleted:
                        modified = True
                    else:
                        empty = False
                        os.write(temp_file, line+"\n")
                    done.append(key)
                else:
                    modified = True

        # write remaining key/value pairs
        if len(self.p_config) > 0:
            for (key,value) in self.p_config.items():
                if key in done:
                    continue
                if not empty:
                    os.write(temp_file, "\n")
                    empty = True
                os.write(temp_file, '%s = %s\n' % (key, value))
                modified = True

        file.close()
        os.close(temp_file)

        if not modified: # not modified: remove tempfile
            os.remove(temp)
            return
        # make backup
        if os.path.exists(self.filename):
            try:
                shutil.copy2(self.filename, "%s.old" % self.filename)
            except Exception, msg:
                os.remove(temp)
                raise IOError, "Backup of '%s' failed: %s" % (self.filename,
                                                              msg)

        # copy tempfile
        try:
            shutil.copy(temp, self.filename)
        except Exception, msg:
            os.remove(temp)
            raise IOError, "Failed to create '%s': %s" % (self.filename, msg)
        else:
            os.remove(temp)
            os.chmod(self.filename, 0644)

    def reload(self):
        return os.system("/sbin/sysctl -p '%s' >/dev/null" % self.filename)
