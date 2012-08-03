#
# Copyright (C) 2007, 2009 Red Hat, Inc.
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

import sys, types, os.path

# import s-c-nw device list
#sys.path.append("/usr/share/system-config-network")
#from netconfpkg import NCDeviceList

from fw_config import *
import fw_services
import fw_icmp
from fw_functions import getPortID, getServiceName, getPortRange, checkIP, \
    checkInterface
from fw_parser import *
from fw_sysconfig import *
import fw_iptables

from snack import *

class ui:
    def init(self):
        # snack
        self.screen = SnackScreen()
        self.screen.drawRootText(0, 0, APP_NAME)
        #self.screen.popHelpLine()
        self.config = None
        self.toplevel = GridForm(self.screen, _("Firewall Configuration"), 1, 6)

        tr = TextboxReflowed(
            50, _("A firewall protects against unauthorized network intrusions. Enabling a firewall blocks all incoming connections. Disabling a firewall allows all connections and is not recommended. "))
        self.toplevel.add(tr, 0, 0, padding=(0,0,0,1), growx=1)

        grid = Grid(2, 1)
        grid.setField(Label(_("Firewall:")), 0, 0, padding=(0,0,1,0))
        self.enabled = Checkbox(_("Enabled"))
        grid.setField(self.enabled, 1, 0, padding=(0,0,0,0))

        self.toplevel.add(grid, 0, 1, padding=(0,0,0,1))

        self.toplevel.bb = ButtonBar(self.screen,
                                     ((_("OK"), "ok"),
                                      (_("Customize"), "customize"),
                                      (_("Cancel"), "cancel")))
        self.toplevel.add(self.toplevel.bb, 0, 3, growx=1)


        self.tabs = [ ]

        # trusted services
        tab = GridForm(self.screen, _("Trusted Services"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Here you can define which services are trusted. Trusted services are accessible from all hosts and networks."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=1)
        self.services = CheckboxTree(6, scroll=1)
        keys = [ svc.name for svc in fw_services.service_list ]
        keys.sort()
        for key in keys:
            svc = fw_services.getByName(key)
            self.services.append(svc.name, svc, selected=False)
        tab.add(self.services, 0, 3, padding=(0,0,1,1), anchorTop=1, growx=1)
        self.tabs.append(tab)

        # other ports
        tab = GridForm(self.screen, _("Other Ports"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Add additional ports or port ranges, which need to be accessible for all hosts or networks."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=1)        
        self.other_ports_box = Listbox(4, scroll=1)
        self.other_ports = [ ]
        tab.bb_work = ButtonBar(self.screen,
                                ((_("Add"), "ports_add"),
                                 (_("Edit"), "ports_edit"),
                                 (_("Remove"), "ports_remove")),
                                compact=1)
        grid = Grid(1, 2)
        grid.setField(self.other_ports_box, 0, 0, padding=(0,0,0,0),
                      anchorTop=1)
        grid.setField(tab.bb_work, 0, 1, padding=(0,0,0,0), anchorTop=1)
        tab.add(grid, 0, 3, padding=(0,0,1,1), anchorTop=1)
        self.tabs.append(tab)

        # trusted interfaces
        tab = GridForm(self.screen, _("Trusted Interfaces"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Mark all interfaces as trusted which should have full access to the system."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=1)        
        self.trust = CheckboxTree(4, scroll=1)

        tab.add(self.trust, 0, 3, padding=(0,0,1,1), anchorTop=1)
        self.tabs.append(tab)

        # masquerading
        tab = GridForm(self.screen, _("Masquerading"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Mark the interfaces to be masqueraded."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=0, anchorLeft=1, anchorTop=1)        
        self.masq = CheckboxTree(4, scroll=1)

        tab.add(self.masq, 0, 4, padding=(0,0,1,1), anchorTop=1)
        self.tabs.append(tab)

        # port forwarding
        tab = GridForm(self.screen, _("Port Forwarding"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Add entries to forward ports either from one port to another on the local system or from the local system to another system. Forwarding to another system is only useful if the interface is masqueraded. Port forwarding is IPv4 only."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=1, anchorLeft=1, anchorTop=1)        
        self.forward_port_box = Listbox(4, scroll=1)
        self.forward_port = [ ]

        tab.bb_work = ButtonBar(self.screen,
                                ((_("Add"), "forward_port_add"),
                                 (_("Edit"), "forward_port_edit"),
                                 (_("Remove"), "forward_port_remove")),
                                compact=1)
        grid = Grid(1, 2)
        grid.setField(self.forward_port_box, 0, 0, padding=(0,0,0,0),
                      anchorTop=1)
        grid.setField(tab.bb_work, 0, 1, padding=(0,0,0,0), anchorTop=1)
        tab.add(grid, 0, 3, padding=(0,0,1,1), anchorTop=1)

        self.tabs.append(tab)

        # icmp filter
        tab = GridForm(self.screen, _("ICMP Filter"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Mark the ICMP types in the list, which should be rejected. All other ICMP types are allowed to pass the firewall. The default is no limitation."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=0, anchorLeft=1, anchorTop=1)
        self.block_icmp = CheckboxTree(4, scroll=1)
        for icmp in fw_icmp.icmp_list:
            self.block_icmp.append(icmp.name, selected=False)
        tab.add(self.block_icmp, 0, 4, padding=(0,0,1,1), anchorTop=1)

        self.tabs.append(tab)

        tab = GridForm(self.screen, _("Custom Rules"), 1, 6)
        tab.bb = None
        tab.bb_work = None
        tr = TextboxReflowed(
            60, _("Use custom rules files to add additional rules to the firewall. The custom rules are added after the default rules. The files must have the iptables-save format."))
        tab.add(tr, 0, 2, padding=(0,0,0,1), growx=1, anchorLeft=1, anchorTop=1)

        self.custom_rules_box = Listbox(4, scroll=1)
        self.custom_rules = [ ]

        tab.bb_work = ButtonBar(self.screen,
                                ((_("Add"), "custom_rules_add"),
                                 (_("Edit"), "custom_rules_edit"),
                                 (_("Remove"), "custom_rules_remove")),
                                compact=1)

        grid = Grid(1, 2)
        grid.setField(self.custom_rules_box, 0, 0, padding=(0,0,0,0),
                      anchorTop=1)
        grid.setField(tab.bb_work, 0, 1, padding=(0,0,0,0), anchorTop=1)
        tab.add(grid, 0, 3, padding=(0,0,1,1), anchorTop=1)

        self.tabs.append(tab)

        # add buttons to all tabs

        for i in xrange(len(self.tabs)):
            tab = self.tabs[i]
            buttons = [ ]
            if i < len(self.tabs) - 1:
                buttons.append((_("Forward"), "forward"))
            if i > 0:
                buttons.append((_("Back"), "back"))
            buttons.append((_("Close"), "close"))
            tab.bb = ButtonBar(self.screen, buttons)
            tab.add(tab.bb, 0, 5, anchorRight=1)

    def loadConfig(self, config):
        self.config = config

        if self.config.enabled:
            self.enabled.setValue("*")
        else:
            self.enabled.setValue(" ")

        # get network devices
        devices = [ ]
        for dev in STD_DEVICES:
            devices.append(dev+"+")

#        try:
#            list = NCDeviceList.getDeviceList()
#        except:
#            pass
#        else:
#            for dev in list:
#                if dev.Alias and dev.Alias != "":
#                    # ignore device aliases: not usable for iptables
#                    continue
#                if not dev.Device in devices:
#                    devices.append(dev.Device)

        if config.trust:
            for dev in config.trust:
                if dev not in devices:
                    devices.append(dev)
        if config.masq:
            for dev in config.masq:
                if dev not in devices:
                    devices.append(dev)
        devices.sort()

        for dev in devices:
            self.trust.append(dev, selected=False)
            self.masq.append(dev, selected=False)

        # trusted services
        for svc in fw_services.service_list:
            enabled = False
            if svc.key in config.services:
                enabled = True
            self.services.setEntryValue(svc, selected=enabled)

        # other ports
        self.other_ports_box.clear()
        self.other_ports = [ ]
        if config.ports:
            for entry in config.ports:
                str = self._portStr(entry[0], entry[1])
                if str not in self.other_ports:
                    self.other_ports.append(entry)
                    self.other_ports_box.append(str, entry)

        # trusted interfaces
        for dev in devices:
            enabled = False
            if config.trust and dev in config.trust:
                enabled = True
            self.trust.setEntryValue(dev, selected=enabled)            

        # masquerading
        for dev in devices:
            enabled = False
            if config.masq and dev in config.masq:
                enabled = True
            self.masq.setEntryValue(dev, selected=enabled)            

        # port forwarding
        self.forward_port_box.clear()
        self.forward_port = [ ]
        if config.forward_port:
            for fwd in config.forward_port:
                array = ( fwd["if"], fwd["proto"], fwd["port"],
                          (fwd["toaddr"] if fwd.has_key("toaddr") else ""),
                          (fwd["toport"] if fwd.has_key("toport") else "") )
                if array not in self.forward_port:

                    line = "%s %s ->" % (fwd["if"], self._portStr(fwd["port"],
                                                                  fwd["proto"]))
                    if fwd.has_key("toaddr"):
                        line += " %s" % fwd["toaddr"]
                    if fwd.has_key("toport"):
                        line += " %s" % self._portStr(fwd["toport"],
                                                      fwd["proto"])
                    self.forward_port.append(array)
                    self.forward_port_box.append(line, array)        

        # icmp filer
        for icmp in fw_icmp.icmp_list:
            enabled = False
            if icmp.key in self.config.block_icmp:
                enabled = True
            self.block_icmp.setEntryValue(icmp.name, selected=enabled)

        # custom rules
        self.custom_rules_box.clear()
        self.custom_rules = [ ]
        if config.custom_rules:
            for entry in config.custom_rules:
                if entry not in self.custom_rules:
                    line = ':'.join(entry)
                    self.custom_rules.append(entry)
                    self.custom_rules_box.append(line, entry)

    def _portStr(self, port, proto):
        if len(port) == 1:
            return "%s:%s" % (port[0], proto)
        else:
            return "%s-%s:%s" % (port[0], port[1], proto)

    def __simplePortStr(self, port):
        if len(port) == 1:
            return "%s" % port[0]
        else:
            return "%s-%s" % (port[0], port[1])

    def _forwardStr(self, interface, protocol, port, to_address, to_port):
        line = "%s %s ->" % (interface, self._portStr(port, protocol))
        if to_address:
            line += " %s" % to_address
        if to_port:
            line += " %s" % self._portStr(to_port, protocol)
        return line

    def dialog(self, type, text, text2=None, buttons=((_("OK"), "ok"),)):
        dialog = GridForm(self.screen, type, 1, 3)
        dialog.add(TextboxReflowed(40, text), 0, 0, padding=(0,0,0,1),
                   anchorLeft=1, growx=1)
        if text2:
            dialog.add(TextboxReflowed(40, text2), 0, 1, padding=(0,0,0,1),
                       anchorLeft=1, growx=1)
        bb = ButtonBar(self.screen, buttons)
        dialog.add(bb, 0, 2, growx=1)
        ret = bb.buttonPressed(dialog.runPopup())
        self.screen.popWindow()
        return ret

    def error(self, text, text2=None, buttons=((_("OK"), "ok"),)):
        return self.dialog(_("Error"), text, text2, buttons)

    def warning(self, text, text2=None, buttons=((_("OK"), "ok"),)):
        return self.dialog(_("Warning"), text, text2, buttons)

    def port_error(self, port):
        self.error(_("Port or port range '%s' is not valid.") % port,
                   _("Valid values: <port>[-<port>], where "
                     "port is either a number [0..65535] "
                     "or a service name."))

    def protocol_error(self, protocol):
        self.error(_("Protocol '%s' is not valid.") % protocol,
                   _("Valid values: tcp, udp"))

    def port_selection(self, port=None, protocol=None):
        _port = ( self.__simplePortStr(port) if port else "" )
        _protocol = ( protocol if protocol else "" )
        while 1:
            (res, values) = EntryWindow(\
                self.screen, ("Port and Protocol"),
                _("Please enter a port or port range and protocol."),
                ((_("Port / Port Range:"), _port),
                 (_("Protocol:"), _protocol)),
                buttons=((_("OK"), "ok"), (_("Cancel"), "cancel")))
            self.screen.popWindow()

            if res == 'ok':
                error = False
                # port
                _port = values[0].strip()
                port = getPortRange(_port)
                if not (isinstance(port, types.ListType) or \
                            isinstance(port, types.TupleType)):
                    self.port_error(_port)
                    error = True
                    port = None
                # protocol
                _protocol = values[1].strip()
                if not _protocol in [ "tcp", "udp" ]:
                    self.protocol_error(_protocol)
                    error = True
                else:
                    protocol = _protocol

                if error:
                    continue
                return (port, protocol)
            elif res == 'cancel':
                return None

    def forward_port_selection(self, interface=None, protocol=None, port=None,
                               to_address=None, to_port=None):
        _interface = ( interface if interface else "" )
        _protocol = ( protocol if protocol else "" )
        _port = ( self.__simplePortStr(port) if port else "" )
        _to_address = ( to_address if to_address else "" )
        _to_port = ( self.__simplePortStr(to_port) if to_port else "" )
        while 1:
            dialog = GridForm(self.screen, _("Port Forwarding"), 1, 6)
            tr = TextboxReflowed(40, _("Please select the source and "
                                       "destination options according "
                                       "to your needs."))
            dialog.add(tr, 0, 0, padding=(0,0,0,1), growx=1)

            dialog.add(TextboxReflowed(40, _("Source (all needed)")), 0, 1,
                       padding=(0,0,0,0), growx=1, anchorLeft=1)

            grid = Grid(2, 3)

            grid.setField(Label(_("Interface:")), 0, 0,
                          padding=(0,0,1,0), anchorLeft=1)
            dialog.interface = Entry(20, text=_interface)
            grid.setField(dialog.interface, 1, 0, padding=(0,0,1,0),
                          anchorLeft=1)

            grid.setField(Label(_("Protocol:")), 0, 1,
                          padding=(0,0,1,0), anchorLeft=1)
            dialog.protocol = Entry(20, text=_protocol)
            grid.setField(dialog.protocol, 1, 1, padding=(0,0,1,0),
                          anchorLeft=1)

            grid.setField(Label(_("Port / Port Range:")), 0, 2,
                          padding=(0,0,1,0), anchorLeft=1)
            dialog.port = Entry(20, text=_port)
            grid.setField(dialog.port, 1, 2, padding=(0,0,1,0),
                          anchorLeft=1)

            dialog.add(grid, 0, 2, padding=(0,0,0,1))

            dialog.add(TextboxReflowed(40, _("Destination (at least one "
                                             "needed)")), 0, 3,
                       padding=(0,0,0,0), growx=1, anchorLeft=1)

            grid = None
            grid = Grid(2, 2)

            grid.setField(Label(_("IP address:")), 0, 0,
                          padding=(0,0,1,0), anchorLeft=1)
            dialog.to_address = Entry(20, text=_to_address)
            grid.setField(dialog.to_address, 1, 0, padding=(0,0,1,0),
                          anchorLeft=1)

            grid.setField(Label(_("Port / Port Range:")), 0, 1,
                          padding=(0,0,1,0), anchorLeft=1)
            dialog.to_port = Entry(20, text=_to_port)
            grid.setField(dialog.to_port, 1, 1, padding=(0,0,1,0),
                          anchorLeft=1)

            dialog.add(grid, 0, 4, padding=(0,0,0,1))
            dialog.bb = ButtonBar(self.screen,
                                  ((_("OK"), "ok"), (_("Cancel"), "cancel")))
            dialog.add(dialog.bb, 0, 5, growx=1)
            res = dialog.bb.buttonPressed(dialog.runPopup())
            self.screen.popWindow()
            values = (dialog.interface.value(), dialog.protocol.value(),
                      dialog.port.value(), dialog.to_address.value(),
                      dialog.to_port.value())

            if res == 'ok':
                error = False
                # interface
                _interface = values[0].strip()
                if not len(_interface) > 0 or not checkInterface(_interface):
                    self.error(_("Interface '%s' is not valid.") % _interface)
                    error = True
                else:
                    interface = _interface
                # protocol
                _protocol = values[1].strip()
                if not _protocol in [ "tcp", "udp" ]:
                    self.protocol_error(_protocol)
                    error = True
                else:
                    protocol = _protocol
                # port
                _port = values[2].strip()
                port = getPortRange(_port)
                if not (isinstance(port, types.ListType) or \
                            isinstance(port, types.TupleType)):
                    self.port_error(_port)
                    error = True
                    port = None
                # to_address
                _to_address = values[3].strip()
                if len(_to_address) > 0 and not checkIP(_to_address):
                    self.error(_("Address '%s' is not valid.") % _to_address)
                    error = True
                    to_address = None
                else:
                    to_address = _to_address
                # to_port
                _to_port = values[4].strip()
                if len(_to_port) > 0:
                    to_port = getPortRange(_to_port)
                    if not (isinstance(to_port, types.ListType) or \
                                isinstance(to_port, types.TupleType)):
                        self.port_error(_to_port)
                        error = True
                        to_port = None

                if error:
                    continue
                if not interface or not protocol or not port:
                    continue
                if not to_address and not to_port:
                    continue

                return (interface, protocol, port, to_address, to_port)
            elif res == 'cancel':
                return None

    def custom_rules_selection(self, type=None, table=None, filename=None):
        _type = ( type if type else "" )
        _table = ( table if table else "" )
        _filename = ( filename if filename else "" )
        while 1:
            (res, values) = EntryWindow(\
                self.screen, ("Custom Rules File"),
                _("Please select the protocol type, the firewall table and "
                  "the file containing the rules."),
                ((_("Protocol Type"), _type), (_("Firewall Table"), _table),
                 (_("File"), _filename )),
                buttons=((_("OK"), "ok"), (_("Cancel"), "cancel")))
            self.screen.popWindow()

            if res == 'ok':
                error = False
                # type
                _type = values[0].strip()
                if not _type in FIREWALL_TYPES:
                    self.error(_("The protocol type '%s' is not "
                                 "valid.") % _type,
                               _("Valid values: %s") % ",".join(FIREWALL_TYPES))
                    error = True
                    type = None
                else:
                    type = _type
                # table
                _table = values[1].strip()
                if not _table in FIREWALL_TABLES:
                    self.error(_("The firewall table '%s' is not "
                                 "valid.") % _table,
                               _("Valid values: %s") % \
                                   ",".join(FIREWALL_TABLES))
                    error = True
                    table = None
                else:
                    table = _table
                # filename
                _filename = values[2].strip()
                if not _filename or not os.path.exists(_filename) or \
                        not os.path.isfile(_filename):
                    self.error(_("The file '%s' does not exist.") % _filename)
                    error = True
                    filename = None
                else:
                    filename = _filename
                # ipv6 has no nat support
                if type == "ipv6" and table == "nat":
                    self.error(_("IPv6 has no nat support."))
                    error = True

                if error:
                    continue
                return (type, table, filename)
            elif res == 'cancel':
                return None

    def finish(self):
        self.screen.finish()

    def genArgs(self):
        # With the new enabled/disabled behavior, we have to ignore the config
        # file or else you can only ever turn on services.
        args = [ "/usr/sbin/lokkit", '-f', '-v' ]

        if self.enabled.selected():
            args.append('--enabled')
        else:
            args.append('--disabled')

        # trusted interfaces
        for dev in self.trust.getSelection():
            args.append("--trust=%s" % dev)

        # masquerading
        for dev in self.masq.getSelection():
            args.append("--masq=%s" % dev)

        # trusted services
        selected = self.services.getSelection()
        for svc in fw_services.service_list:
            if svc in selected:
                args.append("--service=%s" % svc.key)
                for module in svc.modules:
                    args.append("--addmodule=%s" % module)
            else:
                if self.config and self.config.services and \
                        svc.key in self.config.services:
                    for module in svc.modules:
                        args.append("--removemodule=%s" % module)

        # other ports
        for (port, proto) in self.other_ports:
            args.append("--port=%s" % self._portStr(port, proto))

        # port forwarding
        for entry in self.forward_port:
            line = "--forward-port=if=%s:port=%s:proto=%s" % \
                (entry[0], self.__simplePortStr(entry[2]), entry[1])
            if entry[4]:
                line += ":toport=%s" % self.__simplePortStr(entry[4])
            if entry[3]:
                line += ":toaddr=%s" % entry[3]
            args.append(line)

        # icmp filter
        for name in self.block_icmp.getSelection():
            icmp = fw_icmp.getByName(name)
            args.append("--block-icmp=%s" % icmp.key)

        # custom rules
        for (type, table, filename) in self.custom_rules:
            args.append("--custom-rules=%s:%s:%s" % (type, table, filename))

        return args

    def apply(self):
        args = self.genArgs()

        res = self.warning(_("Clicking the 'Yes' button will override "
                             "any existing firewall configuration. "
                             "Are you sure that you want to do this?"),
                           _("Please remember to check if the services "
                             "iptables and ip6tables are enabled."),
                           buttons=((_("Yes"), "yes"), (_("No"), "no")))
        if res == 'no':
            return None

        (rfd, wfd) = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(rfd)
                fd = os.open("/dev/null", os.O_RDONLY)
                if fd != 0:
                    os.dup2(fd, 0)
                    os.close(fd)
                if wfd != 1:
                    os.dup2(wfd, 1)
                    os.close(wfd)
                os.dup2(1, 2)
                os.execv(args[0], args)
            finally:
                os._exit(255)

        os.close(wfd)
        # no need to read in chunks if we don't pass on data to some
        # output func
        cret = ""
        cout = os.read(rfd, 8192)
        while cout:
            cret += cout
            cout = os.read(rfd, 8192)
        os.close(rfd)
        (cpid, status) = os.waitpid(pid, 0)

        # failed to configure firewall, show error message
        if status != 0:
            # do not use dialog, message can be long
            self.screen.suspend()
            print
            print _("Configuration failed")
            print " ".join(args)
            print cret
            print _("Hit enter to continue.")
            raw_input()
            self.screen.resume()
            return 1

        return 0

    def readFile(self):
        self.ignore_all = False
        config = read_sysconfig_config()
        if not config:
            # create empty config object
            config = parseSysconfigArgs(["--disabled"], source=None)
        self.loadConfig(config)

        # Check if firewall config files exist
        if config.enabled and not \
                (os.path.exists(IP4TABLES_RULES) and \
                 os.path.isfile(IP4TABLES_RULES) and \
                 os.path.exists(IP6TABLES_RULES) and \
                 os.path.isfile(IP6TABLES_RULES)):

            files = [ ]
            if not os.path.exists(IP4TABLES_RULES) or \
                    not os.path.isfile(IP4TABLES_RULES):
                files.append(IP4TABLES_RULES)
            if not os.path.exists(IP6TABLES_RULES) or \
                    not os.path.isfile(IP6TABLES_RULES):
                files.append(IP6TABLES_RULES)

            self.warning(_("The firewall configuration is not consistent."),
                         _("The following files are missing or unusable:\n"
                           "\t%s\n\n"
                           "Apply your firewall configuration now to correct "
                           "this problem.") % "\n\t".join(files))

        if config.converted:
            self.warning(_("Old firewall configuration."),
                         _("Your firewall configuration was converted from an "
                           "old version. Please verify the configuration and "
                           "apply."))

        return config

    def parse_error(self, msg):
        if self.ignore_all:
            return
        result = self.dialog(_("Parse error in config file"), msg,
                             buttons=((_("Ignore"), "ignore"),
                                      (_("Ignore All"), "ignore_all"),
                                      (_("Quit"), "quit")))
        if result == "ignore_all":
            self.ignore_all = True
        elif result != "ignore":
            self.finish()
            sys.exit(2)

    def parse_exit(self, status=0):
        sys.exit(status)

    def main(self):
        while 1:
            res = self.toplevel.runPopup()
            str = self.toplevel.bb.buttonPressed(res)
            self.screen.popWindow()

            if str == 'ok':
                if self.apply() == 0:
                    return True
            elif str == 'cancel':
                return False
            elif str == 'customize':
                if not self.enabled.selected():
                    self.error(_("The firewall is disabled."))
                    continue
                self.tab_pos = 0
                while 1:
                    res2 = self.tabs[self.tab_pos].runPopup()
                    self.screen.popWindow()
                    str = self.tabs[self.tab_pos].bb.buttonPressed(res2)
                    if not str and self.tabs[self.tab_pos].bb_work:
                        str = self.tabs[self.tab_pos].bb_work.buttonPressed(res2)
                    if str == 'close':
                        break
                    elif str == 'back':
                        self.screen.refresh()
                        if self.tab_pos > 0:
                            self.tab_pos -= 1
                    elif str == 'forward':
                        self.screen.refresh()
                        if self.tab_pos < len(self.tabs):
                            self.tab_pos += 1

                    # other ports
                    elif str == 'ports_add':
                        res3 = self.port_selection()
                        if res3 and res3 not in self.other_ports:
                            str = self._portStr(res3[0], res3[1])
                            self.other_ports.append(res3)
                            self.other_ports_box.append(str, res3)
                    elif str == 'ports_edit':
                        try:
                            item = self.other_ports_box.current()
                        except:
                            pass
                        else:
                            (ports, proto) = item
                            res3 = self.port_selection(ports, proto)
                            if res3 and res3 not in self.other_ports:
                                self.other_ports.remove(item)
                                self.other_ports_box.delete(item)
                                str = self._portStr(res3[0], res3[1])
                                self.other_ports.append(res3)
                                self.other_ports_box.append(str, res3)
                    elif str == 'ports_remove':
                        try:
                            item = self.other_ports_box.current()
                        except:
                            pass
                        else:
                            self.other_ports.remove(item)
                            self.other_ports_box.delete(item)

                    # forward port
                    elif str == 'forward_port_add':
                        res3 = self.forward_port_selection()
                        if res3 and res3 not in self.forward_port:
                            str = self._forwardStr(res3[0], res3[1], res3[2],
                                                   res3[3], res3[4])
                            self.forward_port.append(res3)
                            self.forward_port_box.append(str, res3)
                    elif str == 'forward_port_edit':
                        try:
                            item = self.forward_port_box.current()
                        except:
                            pass
                        else:
                            (interface, proto, port, to_address, to_port) = item
                            res3 = self.forward_port_selection(interface, proto,
                                                               port, to_address,
                                                               to_port)
                            if res3 and res3 not in self.forward_port:
                                self.forward_port.remove(item)
                                self.forward_port_box.delete(item)
                                str = self._forwardStr(res3[0], res3[1],
                                                       res3[2], res3[3],
                                                       res3[4])
                                self.forward_port.append(res3)
                                self.forward_port_box.append(str, res3)
                    elif str == 'forward_port_remove':
                        try:
                            item = self.forward_port_box.current()
                        except:
                            pass
                        else:
                            self.forward_port.remove(item)
                            self.forward_port_box.delete(item)

                    # custom rules
                    elif str == 'custom_rules_add':
                        res3 = self.custom_rules_selection()
                        if res3 and res3 not in self.custom_rules:
                            str = ":".join(res3)
                            self.custom_rules.append(res3)
                            self.custom_rules_box.append(str, res3)
                    elif str == 'custom_rules_edit':
                        try:
                            item = self.custom_rules_box.current()
                        except:
                            pass
                        else:
                            (type, table, filename) = item
                            res3 = self.custom_rules_selection(type, table,
                                                               filename)
                            if res3 and res3 not in self.custom_rules:
                                self.custom_rules.remove(item)
                                self.custom_rules_box.delete(item)
                                str = ":".join(res3)
                                self.custom_rules.append(res3)
                                self.custom_rules_box.append(str, res3)
                    elif str == 'custom_rules_remove':
                        try:
                            item = self.custom_rules_box.current()
                        except:
                            pass
                        else:
                            self.custom_rules.remove(item)
                            self.custom_rules_box.delete(item)

    def run(self):
        self.init()
        self.readFile()
        res = self.main()
        self.finish()
        return res
