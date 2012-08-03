#
# Copyright (C) 2002, 2003, 2004, 2007, 2008 Red Hat, Inc.
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Chris Lumens <clumens@redhat.com>
# Brent Fox <bfox@redhat.com>
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

import gtk
import gtk.glade
import gobject
import pango
import sys
import os
import socket
import types
import gtk_label_autowrap
import etc_services

# import s-c-nw device list
#sys.path.append("/usr/share/system-config-network")
#from netconfpkg import NCDeviceList

from fw_config import *
import fw_services
import fw_icmp
from fw_functions import getPortID, getServiceName, getPortRange, checkIP, \
    checkInterface
from gtk_treeviewtooltips import TreeViewTooltips
from gtk_chooserbutton import ChooserButton
from fw_parser import *
from fw_sysconfig import *
import fw_iptables
import fw_dbus
import fw_nm

# get icon theme
icon_theme = gtk.icon_theme_get_default()

gtk.glade.bindtextdomain(DOMAIN)

# load xml file, initialize icon theme and set LOKKIT_PROG
if os.access(GLADE_NAME, os.F_OK):
    xml = gtk.glade.XML(GLADE_NAME, domain=DOMAIN)
    icon_theme.append_search_path("./icons")
    LOKKIT_PROG = "./lokkit"
else:
    xml = gtk.glade.XML(DATADIR + "/" + GLADE_NAME, domain=DOMAIN)
    icon_theme.append_search_path(DATADIR)
    LOKKIT_PROG = "/usr/sbin/lokkit"

class ui:
    # You must specify a runPriority for the firstboot module order
    runPriority = 50
    moduleName = _("Firewall")
    commentTag = _("Configure firewall rules")
    shortMessage = _("A firewall allows other computers to access "
                     "selected services on your computer and helps to prevent "
                     "unauthorized access beyond these selections. Select the "
                     "services to which the firewall should allow access.")

    def destroy(self, args):
        gtk.main_quit()

    def __init__(self, use_dbus=True):
        self.xml = xml
        self.dirty = False
        self.enabled = True
        self.doDebug = None
        self.custom_file = None
        self.clean_config = True
        self.config = None
        self.skill = None
        self.fwd_to_local = "- "+_("local")+" -"
        self.use_dbus = use_dbus
        self.mainWindow = None
        self.icon = None
        self.logo = None
        self.dbus_proxy = None

        if os.geteuid() == 0:
            self.use_dbus = False

        if self.use_dbus:
            while not self.dbus_proxy:
                try:
                    self.dbus_proxy = fw_dbus.DBusProxy()
                except Exception, e:
                    self.dbus_error("%s" % e)

#            authorized = 0
#            while not authorized:
#                try:
#                    authorized = self.dbus_proxy.auth()
#                except Exception, e:
#                    print "%s: %s" % (APP_NAME, e)
#                    sys.exit(2)

    def setupScreen(self):
        (width, height) = gtk.icon_size_lookup(gtk.ICON_SIZE_MENU)
        size = min(width, height)

        icon_info = icon_theme.lookup_icon("preferences-system-firewall",
                                           size, 0)
        if icon_info:
            self.icon = icon_info.load_icon()

        icon_info = icon_theme.lookup_icon("preferences-system-firewall",
                                           48, 0)
        if icon_info:
            self.logo = icon_info.load_icon()

        self.mainWindow = self.xml.get_widget("mainWindow")
        self.mainWindow.set_icon(self.icon)
        gtk_label_autowrap.set_autowrap(self.mainWindow)

        self.mainHPaned = self.xml.get_widget("mainHPaned")

        self.notebook = self.xml.get_widget("mainNotebook")
        self.mainVBox = self.xml.get_widget("mainVBox")

        self.menu_apply = self.xml.get_widget("menu_apply")
        self.menu_apply.connect("activate", self.apply)
        self.menu_apply.set_sensitive(False)
        self.menu_reload = self.xml.get_widget("menu_reload")
        self.menu_reload.connect("activate", self.readFile)
        self.menu_quit = self.xml.get_widget("menu_quit")
        self.menu_quit.connect("activate", self.quit)

        self.menu_wizard = self.xml.get_widget("menu_wizard")
        self.menu_wizard.connect("activate", self.startWizard)

        self.menu_enable = self.xml.get_widget("menu_enable")
        self.menu_enable.connect("activate", self.enableFirewall)
        self.menu_disable = self.xml.get_widget("menu_disable")
        self.menu_disable.connect("activate", self.disableFirewall)

        self.menu_defaults_server = self.xml.get_widget("menu_defaults_server")
        self.menu_defaults_desktop = \
            self.xml.get_widget("menu_defaults_desktop")
        self.menu_defaults_server.connect("activate", self.defaults, "server")
        self.menu_defaults_desktop.connect("activate", self.defaults, "desktop")

        self.menu_skill_beginner = self.xml.get_widget("menu_skill_beginner")
        self.menu_skill_expert = self.xml.get_widget("menu_skill_expert")
        self.menu_skill_beginner.connect("activate", self.skill_cb, "beginner")
        self.menu_skill_expert.connect("activate", self.skill_cb, "expert")

        self.menu_settings = self.xml.get_widget("menu_settings")
        self.menu_settings.connect("activate", self.settings)

        self.menu_about = self.xml.get_widget("menu_about")
        self.menu_about.connect("activate", self.about)

        self.wizardToolButton = self.xml.get_widget("wizardToolButton")
        self.wizardToolButton.connect("clicked", self.startWizard)

        self.applyToolButton = self.xml.get_widget("applyToolButton")
        self.applyToolButton.connect("clicked", self.apply)
        self.applyToolButton.set_sensitive(False)
        self.reloadToolButton = self.xml.get_widget("reloadToolButton")
        self.reloadToolButton.connect("clicked", self.readFile)

        self.enableToolButton = self.xml.get_widget("enableToolButton")
        self.enableToolButton.connect("clicked", self.enableFirewall)
        self.disableToolButton = self.xml.get_widget("disableToolButton")
        self.disableToolButton.connect("clicked", self.disableFirewall)

        self.aboutDialog = self.xml.get_widget("aboutDialog")
        self.aboutDialog.set_version(VERSION)
        self.aboutDialog.set_authors(AUTHORS)
        self.aboutDialog.set_license(LICENSE)
        self.aboutDialog.set_copyright(COPYRIGHT)
        self.aboutDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.aboutDialog.set_transient_for(self.mainWindow)
        self.aboutDialog.set_modal(True)
        self.aboutDialog.set_icon(self.icon)
        self.aboutDialog.set_logo(self.logo)

        self.wizardDialog = self.xml.get_widget("wizardDialog")
        gtk_label_autowrap.set_autowrap(self.wizardDialog)
        self.wizardDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.wizardDialog.set_transient_for(self.mainWindow)
        self.wizardDialog.set_modal(True)
        self.wizardDialog.set_icon(self.icon)

        self.wizardHeadEventbox = self.xml.get_widget("wizardHeadEventbox")
        self.wizardHeadEventbox.set_state(gtk.STATE_SELECTED)

        self.wizardNotebook = self.xml.get_widget("wizardNotebook")

        self.wizardDialogOKButton = self.xml.get_widget("wizardDialogOKButton")
        self.wizardDialogBackButton = self.xml.get_widget( \
            "wizardDialogBackButton")
        self.wizardDialogBackButton.connect("clicked", self.wizard_tab_back)
        self.wizardDialogForwardButton = self.xml.get_widget( \
            "wizardDialogForwardButton")
        self.wizardDialogForwardButton.connect("clicked",
                                               self.wizard_tab_forward)

        self.wizardNetworkComboBox = self.xml.get_widget( \
            "wizardNetworkComboBox")
        self.wizardNetworkComboBox.connect("changed",
                                           self.change_network_combo_cb)
        self.wizardSkillComboBox = self.xml.get_widget("wizardSkillComboBox")
        self.wizardKeepCheckButton = self.xml.get_widget( \
            "wizardKeepCheckButton")
        self.wizardKeepCheckButton.connect("toggled", 
                                          self.toggleDefaults)
        self.wizardDefaultsHBox = self.xml.get_widget("wizardDefaultsHBox")
        self.wizardDefaultsComboBox = self.xml.get_widget( \
            "wizardDefaultsComboBox")

        self.modifiedLabel = self.xml.get_widget("modifiedLabel")

        self.startupDialog = self.xml.get_widget("startupDialog")

        self.noConfigurationDialog = \
            self.xml.get_widget("noConfigurationDialog")

        self.stagesView = self.xml.get_widget("stagesView")
        self.stagesView.get_selection().connect( \
            "changed", self.change_stage_cb)
        self.stagesStore = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_INT,
                                         gobject.TYPE_BOOLEAN)

        col = gtk.TreeViewColumn("", gtk.CellRendererText(), text=0,
                                 sensitive=2)
        self.stagesView.append_column(col)

        for i in xrange(self.notebook.get_n_pages()):
            tab = self.notebook.get_nth_page(i)
            if tab.get_property("visible"):
                self.stagesStore.append([self.notebook.get_tab_label_text(tab),
                                         i, True])
        self.stagesView.set_model(self.stagesStore)
        self.stagesView.get_selection().select_path(0)
        self.notebook.set_show_tabs(False)

        self.otherPortsView = self.xml.get_widget("otherPortsView")
        self.otherPortsView.connect("row-activated", self.edit_port_cb)
        self.otherPortsView.get_selection().connect( \
            "changed", self.change_ports_selection_cb)
        self.addPortButton = self.xml.get_widget("addPortButton")
        self.editPortButton = self.xml.get_widget("editPortButton")
        self.editPortButton.set_sensitive(False)
        self.removePortButton = self.xml.get_widget("removePortButton")
        self.removePortButton.set_sensitive(False)

        self.statusLabel = self.xml.get_widget("statusLabel")

        # Set up trusted services
        self.serviceView = self.xml.get_widget("serviceView")
        self.serviceView.get_selection().set_mode(gtk.SELECTION_NONE)
        # Columns: trusted, service, port/protocol
        self.serviceStore = gtk.ListStore(gobject.TYPE_BOOLEAN,
                                          gobject.TYPE_STRING,
                                          gobject.TYPE_STRING,
                                          gobject.TYPE_STRING)
        self.serviceView.connect("row-activated", self.view_row_activated,
                                 self.serviceStore, 0)
        self.serviceTooltips = TreeViewTooltips(self.serviceView,
                                                self.set_service_tooltip)
        self.serviceTooltips.set_property("hide-delay", 60*1000)
        
        colToggle = gtk.CellRendererToggle()
        colToggle.connect("toggled", self.view_toggle_cb, self.serviceStore, 0)
        col = gtk.TreeViewColumn('', colToggle, active=0)
        self.serviceView.append_column(col)

        col = gtk.TreeViewColumn(_("Service"), gtk.CellRendererText(), text=1)
        col.set_sort_column_id(1)
        self.serviceView.append_column(col)

        text = gtk.CellRendererText()
        text.set_property("wrap-mode", pango.WRAP_WORD)

        col = gtk.TreeViewColumn(_("Port/Protocol"), text, markup=2)
        col.set_sort_column_id(2)
        col.set_resizable(True)
        col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        col.set_expand(True)
        self.serviceView.append_column(col)
        self.serviceView.connect("size-allocate", self.resize_text_renderer,
                                 col, text)

        col = gtk.TreeViewColumn(_("Conntrack Helper"), gtk.CellRendererText(),
                                 markup=3)
        col.set_sort_column_id(3)
        self.serviceView.append_column(col)
        self.serviceView.set_model(self.serviceStore)
        self.serviceStore.set_sort_column_id(1, gtk.SORT_ASCENDING)

        self.serviceView.set_search_column(1)

        # Set up the view and columns for the Other Ports section.
        self.otherPortsStore = gtk.ListStore(gobject.TYPE_STRING,
                                             gobject.TYPE_STRING,
                                             gobject.TYPE_STRING)

        col = gtk.TreeViewColumn(_("Port"), gtk.CellRendererText(), text=0)
        self.otherPortsStore.set_sort_column_id(0, gtk.SORT_ASCENDING)
        col.set_sort_column_id(0)
        self.otherPortsView.append_column(col)

        col = gtk.TreeViewColumn(_("Protocol"), gtk.CellRendererText(), text=1)
        col.set_sort_column_id(1)
        self.otherPortsView.append_column(col)

        col = gtk.TreeViewColumn(_("Service"), gtk.CellRendererText(), text=2)
        col.set_sort_column_id(2)
        self.otherPortsView.append_column(col)
        self.otherPortsView.set_model(self.otherPortsStore)

        self.addPortButton.connect("clicked", self.add_port_cb)
        self.editPortButton.connect("clicked", self.edit_port_cb)
        self.removePortButton.connect("clicked", self.remove_port_cb)

        # Add port dialog
        self.portDialog = self.xml.get_widget("portDialog")
        gtk_label_autowrap.set_autowrap(self.portDialog)
        self.portDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.portDialog.set_transient_for(self.mainWindow)
        self.portDialogOkButton = self.xml.get_widget("portDialogOkButton")
        self.portDialogOkButton.set_sensitive(False)
        self.portEntry = self.xml.get_widget("portEntry")
        self.portEntry.connect("changed", self.port_entry_changed_cb)
        self.portUserCheckButton = self.xml.get_widget("portUserCheckButton")
        self.portUserCheckButton.connect("clicked", self.toggle_port_user_cb)
        self.portUserTable = self.xml.get_widget("portUserTable")

        # Ports from etc services for add port dialog
        self.etcServicesSW = self.xml.get_widget("etcServicesSW")
        self.etcServicesView = self.xml.get_widget("etcServicesView")
        self.etcServicesView.get_selection().connect( \
            "changed", self.etc_services_selection_cb)
        self.etcServicesView.connect("row-activated",
                                     self.etc_services_selection_ok_cb)
        # gtk.TreeModelFilter is not sortable, therefore using different
        # stores for the protocols: etcServicesStore for tcp and udp, 
        # etcServicesStore_tcp for tcp and etcServicesStore_udp for udp
        self.etcServicesStore = gtk.ListStore(gobject.TYPE_INT,
                                              gobject.TYPE_STRING,
                                              gobject.TYPE_STRING)
        self.etcServicesStore_tcp = gtk.ListStore(gobject.TYPE_INT,
                                              gobject.TYPE_STRING,
                                              gobject.TYPE_STRING)
        self.etcServicesStore_udp = gtk.ListStore(gobject.TYPE_INT,
                                              gobject.TYPE_STRING,
                                              gobject.TYPE_STRING)
        for port in etc_services.services:
            proto = port.getProtocol()
            if proto not in [ "tcp", "udp" ]:
                continue
            entry = [port.getId(), proto, port.getName()]
            self.etcServicesStore.append(entry)
            if proto == "tcp":
                self.etcServicesStore_tcp.append(entry)
            else:
                self.etcServicesStore_udp.append(entry)

        self.etcServicesView_limit_to_proto = None

        col = gtk.TreeViewColumn(_("Port"), gtk.CellRendererText(), text=0)
        col.set_sort_column_id(0)
        self.etcServicesStore.set_sort_column_id(0, gtk.SORT_ASCENDING)
        self.etcServicesView.append_column(col)

        col = gtk.TreeViewColumn(_("Protocol"), gtk.CellRendererText(), text=1)
        col.set_sort_column_id(1)
        self.etcServicesView.append_column(col)

        col = gtk.TreeViewColumn(_("Service"), gtk.CellRendererText(), text=2)
        col.set_sort_column_id(2)
        self.etcServicesView.append_column(col)

        self.etcServicesView.set_model(self.etcServicesStore)

        # Add options to the protocol combo box.
        self.protoCombo = self.xml.get_widget("protoComboBox")
        self.protoCombo.append_text("tcp")
        self.protoCombo.append_text("udp")
        self.protoCombo.set_active(0)

        self.protoLabel = self.xml.get_widget("protoLabel")

        self.interfaceStore = gtk.TreeStore(\
            gobject.TYPE_STRING, # interface
            gobject.TYPE_STRING, # interface description
            gobject.TYPE_BOOLEAN, # trusted
            gobject.TYPE_BOOLEAN, # trusted save
            gobject.TYPE_BOOLEAN, # trusted sensitive
            gobject.TYPE_BOOLEAN, # masqueraded
            gobject.TYPE_BOOLEAN, # masqueraded save
            gobject.TYPE_BOOLEAN  # masqueraded sensitive
            )
        self._if_trust = 2
        self._if_trust_save = 3
        self._if_trust_sensitive = 4
        self._if_masq = 5
        self._if_masq_save = 6
        self._if_masq_sensitive = 7

        self.interfaceDialog = self.xml.get_widget("interfaceDialog")
        gtk_label_autowrap.set_autowrap(self.interfaceDialog)
        self.interfaceDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.interfaceDialog.set_transient_for(self.mainWindow)

        # Set up trusted interfaces
        self.trustedView = self.xml.get_widget("trustedView")
        self.trustedView.get_selection().set_mode(gtk.SELECTION_NONE)
        # Columns: active, interface, description, clicked, sensitive
        self.trustedView.connect("row-activated", self.view_row_activated,
                                 self.interfaceStore, self._if_trust,
                                 self._if_trust_save,
                                 self._if_trust_sensitive)

        colToggle = gtk.CellRendererToggle()
        colToggle.connect("toggled", self.view_toggle_cb, self.interfaceStore,
                          self._if_trust, self._if_trust_save,
                          self._if_trust_sensitive)
        colToggle.connect("toggled", self.view_sensitive_children_cb,
                          self.interfaceStore, self._if_trust,
                          self._if_trust_save, self._if_trust_sensitive)
        col = gtk.TreeViewColumn("", colToggle, active=self._if_trust,
                                 sensitive=self._if_trust_sensitive)
        self.trustedView.append_column(col)

        col = gtk.TreeViewColumn(_("Interface"), gtk.CellRendererText(),
                                 text=0, sensitive=self._if_trust_sensitive)
        col.set_sort_column_id(1)
        self.trustedView.append_column(col)
        self.trustedView.set_expander_column(col)
        self.interfaceStore.set_sort_column_id(1, gtk.SORT_ASCENDING)

        col = gtk.TreeViewColumn(_("Description"), gtk.CellRendererText(),
                                 text=1, sensitive=self._if_trust_sensitive)
        self.trustedView.append_column(col)

        self.trustedView.set_model(self.interfaceStore)

        self.masqueradeView = self.xml.get_widget("masqueradeView")
        self.masqueradeView.get_selection().set_mode(gtk.SELECTION_NONE)
        # Columns: active, interface, description, clicked, sensitive
        self.masqueradeView.connect("row-activated", self.view_row_activated,
                                    self.interfaceStore, self._if_masq,
                                    self._if_masq_save, self._if_masq_sensitive)

        colToggle = gtk.CellRendererToggle()
        colToggle.connect ("toggled", self.view_toggle_cb, self.interfaceStore,
                           self._if_masq, self._if_masq_save,
                           self._if_masq_sensitive)
        colToggle.connect ("toggled", self.view_sensitive_children_cb,
                           self.interfaceStore, self._if_masq,
                           self._if_masq_save, self._if_masq_sensitive)
        col = gtk.TreeViewColumn("", colToggle, active=self._if_masq,
                                 sensitive=self._if_masq_sensitive)
        self.masqueradeView.append_column(col)

        col = gtk.TreeViewColumn(_("Interface"), gtk.CellRendererText(),
                                 text=0, sensitive=self._if_masq_sensitive)
        col.set_sort_column_id(1)
        self.masqueradeView.append_column(col)
        self.masqueradeView.set_expander_column(col)

        col = gtk.TreeViewColumn(_("Description"), gtk.CellRendererText(),
                                 text=1, sensitive=self._if_masq_sensitive)
        self.masqueradeView.append_column(col)

        self.masqueradeView.set_model(self.interfaceStore)

        # interface dialog
        self.interfaceDialog = self.xml.get_widget("interfaceDialog")
        gtk_label_autowrap.set_autowrap(self.interfaceDialog)
        self.interfaceDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.interfaceDialog.set_transient_for(self.mainWindow)
        self.interfaceDialogOkButton = \
            self.xml.get_widget("interfaceDialogOkButton")

        self.interfaceView = self.xml.get_widget("interfaceView")
        self.interfaceView.get_selection().set_mode(gtk.SELECTION_SINGLE)
        self.interfaceView.get_selection().connect( \
            "changed", self.interface_selection_cb)
        self.interfaceView.connect("row-activated",
                                   self.interface_selection_ok_cb)
        
        col = gtk.TreeViewColumn(_("Interface"), gtk.CellRendererText(), text=0)
        col.set_sort_column_id(0)
        self.interfaceView.append_column(col)
        self.interfaceView.set_expander_column(col)
        col = gtk.TreeViewColumn(_("Description"), gtk.CellRendererText(),
                                 text=1)
        self.interfaceView.append_column(col)

        self.interfaceView.set_model(self.interfaceStore)

        self.interfaceUserCheckButton = \
            self.xml.get_widget("interfaceUserCheckButton")
        self.interfaceUserCheckButton.connect("clicked",
                                              self.toggle_interface_user_cb)
        self.interfaceEntry = self.xml.get_widget("interfaceEntry")
        self.interfaceEntry.connect("changed", self.interface_entry_changed_cb)

        # port forward dialog
        self.forwardDialog = self.xml.get_widget("forwardDialog")
        gtk_label_autowrap.set_autowrap(self.forwardDialog)
        self.forwardDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.forwardDialog.set_transient_for(self.mainWindow)

        self.forwardDialogOKButton = \
            self.xml.get_widget("forwardDialogOKButton")
        
        self.forwardInterfaceChooser = ChooserButton(
            self.xml.get_widget("forwardInterfaceChooser"),
            "- "+_("Select")+" -")
        self.forwardInterfaceChooser.connect("clicked",
                                             self.add_forward_interface_cb)

        self.forwardProtocolComboBox = \
            self.xml.get_widget("forwardProtocolComboBox")

        self.forwardPortChooser = \
            ChooserButton(self.xml.get_widget("forwardPortChooser"),
            "- "+_("Select")+" -")
        self.forwardPortChooser.connect("clicked",
                                        self.add_forward_port_cb,
                                        self.forwardPortChooser)

        self.forwardLocalCheckButton = \
            self.xml.get_widget("forwardLocalCheckButton")
        self.forwardLocalCheckButton.connect("clicked",
                                             self.toggle_forward_check_cb)

        self.forwardFwdAddressEntry = \
            self.xml.get_widget("forwardFwdAddressEntry")
        self.forwardFwdAddressEntry.connect("changed", self.check_forward_ok)
        self.forwardFwdAddressLabel = \
            self.xml.get_widget("forwardFwdAddressLabel")
        self.forwardFwdAddressDescriptionHBox = \
            self.xml.get_widget("forwardFwdAddressDescriptionHBox")

        self.forwardOtherPortCheckButton = \
            self.xml.get_widget("forwardOtherPortCheckButton")
        self.forwardOtherPortCheckButton.connect("clicked",
                                                 self.toggle_forward_check_cb)

        self.forwardFwdPortChooser = \
            ChooserButton(self.xml.get_widget("forwardFwdPortChooser"),
            "- "+_("Select")+" -")
        self.forwardFwdPortChooser.connect("clicked",
                                           self.add_forward_port_cb,
                                           self.forwardFwdPortChooser)
        self.forwardFwdPortLabel = self.xml.get_widget("forwardFwdPortLabel")

        # port forwarding
        self.addForwardButton = self.xml.get_widget("addForwardButton")
        self.addForwardButton.connect("clicked", self.add_forward_cb)
        self.editForwardButton = self.xml.get_widget("editForwardButton")
        self.editForwardButton.connect("clicked", self.edit_forward_cb)
        self.removeForwardButton = self.xml.get_widget("removeForwardButton")
        self.removeForwardButton.connect("clicked", self.remove_forward_cb)

        self.forwardView = self.xml.get_widget("forwardView")
        self.forwardView.connect("row-activated", self.edit_forward_cb)
        self.forwardView.get_selection().connect( \
            "changed", self.change_forward_selection_cb)
        self.forwardStore = gtk.ListStore(gobject.TYPE_STRING, # interface
                                          gobject.TYPE_STRING, # protcol
                                          gobject.TYPE_STRING, # port
                                          gobject.TYPE_STRING, # to_address
                                          gobject.TYPE_STRING) # to_port

        col = gtk.TreeViewColumn(_("Interface"), gtk.CellRendererText(), text=0)
        col.set_sort_column_id(0)
        self.forwardView.append_column(col)
        self.forwardStore.set_sort_column_id(0, gtk.SORT_ASCENDING)

        col = gtk.TreeViewColumn(_("Protocol"), gtk.CellRendererText(), text=1)
        col.set_sort_column_id(1)
        self.forwardView.append_column(col)
        col = gtk.TreeViewColumn(_("Port"), gtk.CellRendererText(), text=2)
        col.set_sort_column_id(2)
        self.forwardView.append_column(col)
        col = gtk.TreeViewColumn(_("To Address"), gtk.CellRendererText(),
                                 text=3)
        col.set_sort_column_id(3)
        self.forwardView.append_column(col)
        col = gtk.TreeViewColumn(_("To Port"), gtk.CellRendererText(),
                                 text=4)
        col.set_sort_column_id(4)
        self.forwardView.append_column(col)

        self.forwardView.set_model(self.forwardStore)

        # icmp
        self.icmpView = self.xml.get_widget("icmpView")
        self.icmpView.get_selection().set_mode(gtk.SELECTION_NONE)
        self.icmpStore = gtk.ListStore(gobject.TYPE_BOOLEAN,
                                       gobject.TYPE_STRING,
                                       gobject.TYPE_STRING)
        self.icmpView.connect("row-activated", self.view_row_activated,
                              self.icmpStore, 0)
        self.icmpTooltips = TreeViewTooltips(self.icmpView,
                                             self.set_icmp_tooltip)
        self.icmpTooltips.set_property("hide-delay", 60*1000)

        colToggle = gtk.CellRendererToggle()
        colToggle.connect("toggled", self.view_toggle_cb, self.icmpStore, 0)
        col = gtk.TreeViewColumn('', colToggle, active=0)
        self.icmpView.append_column(col)

        col = gtk.TreeViewColumn(_("ICMP Type"), gtk.CellRendererText(), text=1)
        col.set_sort_column_id(1)
        self.icmpView.append_column(col)

        col = gtk.TreeViewColumn(_("Protocol Type"), gtk.CellRendererText(), text=2)
        col.set_sort_column_id(2)
        self.icmpView.append_column(col)

        self.icmpStore.set_sort_column_id(1, gtk.SORT_ASCENDING)
        self.icmpView.set_search_column(1)

        self.icmpView.set_model(self.icmpStore)

        # custom rules chooser
        self.customRulesChooser = self.xml.get_widget("customRulesChooser")
        self.customRulesChooser.connect("selection-changed",
                                        self.custom_filechooser_cb)
        # set starting directory for custom rules chooser
        self.customRulesChooser.set_current_folder( \
            os.path.dirname(IP4TABLES_RULES))

        # custom rules files
        self.customView = self.xml.get_widget("customView")
        # Columns: active, interface, description, clicked, sensitive
        self.customStore = gtk.ListStore(\
            gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)

        col = gtk.TreeViewColumn(_("Type"), gtk.CellRendererText(),
                                 text=0)
        self.customView.append_column(col)

        col = gtk.TreeViewColumn(_("Table"), gtk.CellRendererText(),
                                 text=1)
        self.customView.append_column(col)

        col = gtk.TreeViewColumn(_("Filename"), gtk.CellRendererText(),
                                 text=2)
        self.customView.append_column(col)

        self.customView.set_model(self.customStore)

        # add/remove custom files
        self.addCustomButton = self.xml.get_widget("addCustomButton")
        self.addCustomButton.connect("clicked", self.add_custom_cb)
        self.editCustomButton = self.xml.get_widget("editCustomButton")
        self.editCustomButton.connect("clicked", self.edit_custom_cb)
        self.removeCustomButton = self.xml.get_widget("removeCustomButton")
        self.removeCustomButton.set_sensitive(False)
        self.removeCustomButton.connect("clicked", self.remove_custom_cb)

        self.upCustomButton = self.xml.get_widget("upCustomButton")
        self.upCustomButton.connect("clicked", self.move_custom_cb)
        self.downCustomButton = self.xml.get_widget("downCustomButton")
        self.downCustomButton.connect("clicked", self.move_custom_cb)

        self.customView.connect("row-activated", self.edit_custom_cb)
        self.customView.get_selection().connect( \
            "changed", self.change_custom_selection_cb)

        self.customDialog = self.xml.get_widget("customDialog")
        gtk_label_autowrap.set_autowrap(self.customDialog)
        self.customDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.customDialog.set_transient_for(self.mainWindow)
        self.customDialog.set_modal(True)
        self.customDialog.set_icon(self.icon)

        self.customDialogOkButton = self.xml.get_widget("customDialogOkButton")

        self.protocolTypeCombo = self.xml.get_widget("protocolTypeCombo")
        self.protocolTypeCombo.connect("changed", self.change_custom_combo_cb)
        self.firewallTableCombo = self.xml.get_widget("firewallTableCombo")

        self.settingsDialog = self.xml.get_widget("settingsDialog")
        gtk_label_autowrap.set_autowrap(self.settingsDialog)
        self.settingsDialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        self.settingsDialog.set_transient_for(self.mainWindow)

        self.settingsView = self.xml.get_widget("settingsView")
        self.settingsView.get_selection().set_mode(gtk.SELECTION_NONE)
        self.settingsStore = gtk.ListStore(gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_BOOLEAN,
                                           gobject.TYPE_BOOLEAN)
        
        self.settingsTooltips = TreeViewTooltips(self.settingsView,
                                                 self.set_settings_tooltip)
        self.settingsTooltips.set_property("hide-delay", 60*1000)
        col = gtk.TreeViewColumn("", gtk.CellRendererText(), text=1)
        col.set_resizable(True)
        col.set_sizing(gtk.TREE_VIEW_COLUMN_AUTOSIZE)
        col.set_expand(True)
        self.settingsView.append_column(col)

        colToggle = gtk.CellRendererToggle()
        colToggle.connect("toggled", self.settings_toggle_cb,
                          self.settingsStore, 2)
        col = gtk.TreeViewColumn("iptables", colToggle, active=2)
        self.settingsView.append_column(col)

        colToggle = gtk.CellRendererToggle()
        colToggle.connect("toggled", self.settings_toggle_cb,
                          self.settingsStore, 3)
        col = gtk.TreeViewColumn("ip6tables", colToggle, active=3)
        self.settingsView.append_column(col)

        self.settingsView.set_model(self.settingsStore)

        self.settingsOKButton = self.xml.get_widget("settingsOKButton")

        self.xml.get_widget("addInterface1Button").connect(\
            "clicked", self.add_interface_cb)
        self.xml.get_widget("addInterface2Button").connect(\
            "clicked", self.add_interface_cb)

        # services
        for svc in fw_services.service_list:
            ports = [ ]
            protos = { }
            for port in svc.ports:
                if port[0]:
                    port_id = getPortID(port[0])
                else:
                    port_id = ""
                protos.setdefault(port[1], []).append(port_id)

            for proto in sorted(protos):
                for port in sorted(protos[proto]):
                    ports.append("%s/%s" % (port, proto))

            if len(ports) == 0:
                ports.append("---")
            modules = [ ]
            for module in svc.modules:
                modules.append(module.replace("nf_conntrack_", ""))
            self.serviceStore.append([False, svc.name, ", ".join(ports),
                                      ", ".join(modules)])

        # global devices
        for dev in STD_DEVICES:
            devplus = "%s+" % dev
            self.addInterface(devplus)

        devices = { }

#        try:
#            devlist = NCDeviceList.getDeviceList()
#        except:
#            devlist = [ ]
#        for device in devlist:
#            if device.Alias and device.Alias != "":
#                # ignore device aliases: not usable for iptables
#                continue
#            devices.setdefault(device.Device, [ ]).append(device)

#        # add local devices
#        for dev in devices:
#            desc = ""
#            for device in devices[dev]:
#                if desc != "":
#                    desc += "\n"
#                if device.DeviceId != "dhcp" and device.DeviceId != dev:
#                    desc += "%s (%s)" % (device.Type, device.DeviceId)
#                else:
#                    desc += device.Type
#                if device.BootProto != "none":
#                    desc += ", %s" % device.BootProto
#                else:
#                    desc += ", %s/%s" % (device.IP, device.Netmask)
#                if device.HardwareAddress:
#                    desc += ", HWADDR %s" % device.HardwareAddress
#                if device.OnBoot:
#                    desc += ", ONBOOT"
#            self.addInterface(dev, desc)

        try:
            devices = fw_nm.device_list()
        except:
            pass

        # add local devices
        for dev in devices:
            desc = devices[dev]["type"]
            desc += ", HWADDR %s" % devices[dev]["hwaddr"]
            self.addInterface(dev, desc)

        self.trustedView.expand_all()
        self.masqueradeView.expand_all()

        # services
        for icmp in fw_icmp.icmp_list:
            type = "ipv4, ipv6"
            if icmp.type and len(icmp.type) > 0:
                type = icmp.type
            self.icmpStore.append([False, icmp.name, type])

        # activate the firewall
        self.setSkillLevel("expert")
        self.firewall_enable()

    def skill_cb(self, arg, level):
        self.skill = level
        show = "all"
        sensitive = True
        if level == "beginner":
            show = [ ]
            show.append(_("Trusted Services"))
            sensitive = False

        self.menu_settings.set_sensitive(sensitive)
        for i in xrange(2, len(self.serviceView.get_columns())):
            for cell in self.serviceView.get_column(i).get_cell_renderers():
                cell.set_property("sensitive", sensitive)
        self.serviceView.columns_autosize()

        for i in xrange(self.notebook.get_n_pages()):
            page = self.notebook.get_nth_page(i)
            name = self.notebook.get_tab_label_text(page)
            value = False
            if show == "all":
                value = True
            elif name in show:
                value = True
            page.set_sensitive(value)
            iter = self.stagesStore.get_iter_first()
            while iter:
                if name == self.stagesStore.get_value(iter, 0):
                    self.stagesStore.set_value(iter, 2, value)
                iter = self.stagesStore.iter_next(iter)
        self.stagesView.get_selection().select_path(0)

    def setSkillLevel(self, level):
        if self.skill == level:
            return True
        if level == "beginner":
            self.menu_skill_beginner.set_active(True)
            self.menu_skill_expert.set_active(False)
        else:
            self.menu_skill_beginner.set_active(False)
            self.menu_skill_expert.set_active(True)

    def toggleDefaults(self, toggle):
        if toggle.get_active():
            self.wizardDefaultsHBox.set_sensitive(False)
        else:
            self.wizardDefaultsHBox.set_sensitive(True)

    def setDirty(self, val):
        self.dirty = val
        self.menu_apply.set_sensitive(self.dirty)
        self.applyToolButton.set_sensitive(self.dirty)
        if val:
            self.modifiedLabel.set_text(_("(modified)"))
        else:
            self.modifiedLabel.set_text("")

    def enableFirewall(self, *args):
        if not self.config:
            result = self._dialog(self.noConfigurationDialog)
            if result == gtk.RESPONSE_CANCEL:
                self.startWizard()
            
        self.firewall_enable()
        self.setDirty(True)

    def disableFirewall(self, *args):
        self.firewall_disable()
        self.setDirty(True)

    def firewall_enable(self):
        self.statusLabel.set_markup("<span color='#008800'>" +\
                                    _("The firewall is enabled.") +\
                                    "</span>")
        self.menu_enable.set_sensitive(0)
        self.menu_disable.set_sensitive(1)
        self.enableToolButton.set_sensitive(0)
        self.disableToolButton.set_sensitive(1)
        self.enabled = True
        self.mainHPaned.set_sensitive(True)

    def firewall_disable(self):
        self.statusLabel.set_markup("<span color='#cc0000'>" +\
                                    _("The firewall is disabled.") +\
                                    "</span>")
        self.menu_enable.set_sensitive(1)
        self.menu_disable.set_sensitive(0)
        self.enableToolButton.set_sensitive(1)
        self.disableToolButton.set_sensitive(0)
        self.enabled = False
        self.mainHPaned.set_sensitive(False)

    def view_row_activated(self, treeview, row, view_column, model, col,
                           save=-1, sensitive=-1):
        if treeview.get_column(col) == view_column:
            # do not enable double click on checkbox
            return

        self.view_toggle_cb(None, row, model, col, save, sensitive)
        if save and sensitive:
            self.view_sensitive_children_cb(None, row, model, col, save,
                                            sensitive)

    def set_service_tooltip(self, model, path, col):
        iter = model.get_iter(path)
        name = model.get(iter, 1)[0]
        svc = fw_services.getByName(name)

        text = "<b>" + name + "</b>"
        if svc.description and len(svc.description) > 0:
            text += "\n" + svc.description
        return text

    def set_icmp_tooltip(self, model, path, col):
        iter = model.get_iter(path)
        name = model.get(iter, 1)[0]
        icmp = fw_icmp.getByName(name)

        text = "<b>" + name + "</b>"
        if icmp.description and len(icmp.description) > 0:
            text += "\n" + icmp.description
        return text

    def set_settings_tooltip(self, model, path, col):
        iter = model.get_iter(path)
        name = model.get(iter, 1)[0]
        setting = fw_iptables.getByName(name)

        text = "<b>" + name + "</b>"
        if setting.description and len(setting.description) > 0:
            text += "\n" + setting.description

        text += "<small>"
        text += "\n<b>" + _("Key:") + "</b> %s" % setting.key
        if setting.iptables or setting.ip6tables:
            text += "\n<b>" + _("Default:") + "</b> "
            if setting.iptables:
                text += "iptables "
            if setting.ip6tables:
                text += "ip6tables "
        text += "</small>"

        return text

    def custom_filechooser_cb(self, *args):
        filename = self.customRulesChooser.get_filename()
        self.customDialogOkButton.set_sensitive(filename != None)

    def view_toggle_cb(self, toggle, row, model, col, save=-1, sensitive=-1):
        iter = model.get_iter(row)
        if sensitive < 0 or model.get(iter, sensitive)[0]:
            old_val = model.get(iter, col)[0]
            model.set(iter, col, not old_val)
            if save >= 0:
                model.set(iter, save, not old_val)
            self.setDirty(True)

    def _setSensitive(self, model, iter, col, clicked_col, sensitive_col, val):
        for i in xrange(model.iter_n_children(iter)):
            iter2 = model.iter_nth_child(iter, i)
            clicked = model.get(iter2, clicked_col)[0]

            # set (in)sensitive
            model.set(iter2, sensitive_col, val)

            if val:
                # set old state
                model.set(iter2, col, clicked)
            else:
                # set new state
                model.set(iter2, col, not val)

            if not clicked or clicked != val:
                self._setSensitive(model, iter2, col, clicked_col,
                                   sensitive_col, val)

    def view_sensitive_children_cb(self, toggle, row, model, col, clicked_col,
                                   sensitive_col):
        iter = model.get_iter(row)
        if sensitive_col >= 0 and not model.get(iter, sensitive_col)[0]:
            return
        self._setSensitive(model, iter, col, clicked_col, sensitive_col,
                           not model.get(iter, col)[0])

    def change_stage_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.notebook.set_current_page(self.stagesStore.get(iter, 1)[0])
        else:
            i = self.notebook.get_current_page()
            selection.select_path(i)

    def resize_text_renderer(self, widget, requisition, col, text):
        old_size = text.get_size(col.get_tree_view(), requisition)
        new_width = col.get_width() - 2 * col.get_spacing() \
            - 2 * text.get_property("xpad")
        if new_width < 1:
            return
        width = text.get_property("wrap-width")
        if width == new_width:
            return
        text.set_property("wrap-width", new_width)
        new_size = text.get_size(col.get_tree_view())
        col.queue_resize()

    def change_ports_selection_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.editPortButton.set_sensitive(True)
            self.removePortButton.set_sensitive(True)
        else:
            self.editPortButton.set_sensitive(False)
            self.removePortButton.set_sensitive(False)

    def change_forward_selection_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.editForwardButton.set_sensitive(True)
            self.removeForwardButton.set_sensitive(True)
        else:
            self.editForwardButton.set_sensitive(False)
            self.removeForwardButton.set_sensitive(False)

    def change_custom_selection_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.editCustomButton.set_sensitive(True)
            self.removeCustomButton.set_sensitive(True)
            idx = model.get_path(iter)[0]
            self.upCustomButton.set_sensitive(idx > 0)
            self.downCustomButton.set_sensitive(idx < len(model)-1)
        else:
            self.editCustomButton.set_sensitive(False)
            self.removeCustomButton.set_sensitive(False)
            self.upCustomButton.set_sensitive(False)
            self.downCustomButton.set_sensitive(False)

    def move_custom_cb(self, button):
        (model, iter) = self.customView.get_selection().get_selected()
        idx = model.get_path(iter)[0]
        if button == self.upCustomButton and idx > 0:
            # move up
            model.swap(iter, model.get_iter(idx-1))
            self.setDirty(True)
            self.change_custom_selection_cb(self.customView.get_selection())
        if button == self.downCustomButton and idx < len(model)-1:
            # move down
            model.swap(iter, model.get_iter(idx+1))
            self.setDirty(True)
            self.change_custom_selection_cb(self.customView.get_selection())

    def _etcServices_visible_filter(self, model, iter):
        if not self.etcServicesView_limit_to_proto:
            return True
        if model.get_value(iter, 1) == self.etcServicesView_limit_to_proto:
            return True
        return False

    def port_selection(self, port=None, proto=None, limit_to_proto=None):
        self.portEntry.set_text("")
        self.protoCombo.set_active(0)
        if len(self.etcServicesStore) > 0:
            self.portUserCheckButton.set_active(False)
            self.portUserCheckButton.set_sensitive(True)
        else:
            self.portUserCheckButton.set_active(True)
            self.portUserCheckButton.set_sensitive(False)

        self.etcServicesView.get_selection().unselect_all()

        old_model =  self.etcServicesView.get_model()
        if limit_to_proto:
            if self.etcServicesView_limit_to_proto != limit_to_proto:
                self.etcServicesView_limit_to_proto = limit_to_proto
                if limit_to_proto == None:
                    self.etcServicesView.set_model(self.etcServicesStore)
                elif limit_to_proto == "tcp":
                    self.etcServicesView.set_model(self.etcServicesStore_tcp)
                elif limit_to_proto == "udp":
                    self.etcServicesView.set_model(self.etcServicesStore_udp)
            self.combobox_select_text(self.protoCombo, limit_to_proto)
            self.protoCombo.set_sensitive(False)
            self.protoLabel.set_sensitive(False)
        else:
            if self.etcServicesView_limit_to_proto != None:
                self.etcServicesView_limit_to_proto = None
                self.etcServicesView.set_model(self.etcServicesStore)
            self.protoCombo.set_sensitive(True)
            self.protoLabel.set_sensitive(True)

        model = self.etcServicesView.get_model()
        if old_model != model:
            sort_column_id = old_model.get_sort_column_id()
            model.set_sort_column_id(sort_column_id[0], sort_column_id[1])

        if port and proto:
            ports = getPortRange(port)
            found = False
            # first try to find ports[0] in the model and select it
            if ports and len(ports) == 1:
                iter = model.get_iter_first()
                while iter:
                    if model.get_value(iter, 0) == ports[0] and \
                            model.get_value(iter, 1) == proto:
                        found = True
                        self.etcServicesView.get_selection().select_iter(iter)
                        self.etcServicesView.set_cursor(model.get_path(iter))
                        break
                    iter = model.iter_next(iter)
            # else set the entry
            if not found:
                self.portUserCheckButton.set_active(True)
                self.portEntry.set_text(port)
                self.combobox_select_text(self.protoCombo, proto)

        self.portDialog.show_all()
        self.portDialogOkButton.set_sensitive(False)

        # Loop until we get a valid port
        while True:
            result = self.portDialog.run()
            if result == gtk.RESPONSE_OK:
                if not self.portUserCheckButton.get_active():
                    selection = self.etcServicesView.get_selection()
                    (model, iter) = selection.get_selected()
                    if not iter:
                        continue
                    port = model.get(iter, 0)[0]
                    proto = model.get(iter, 1)[0]
                else:
                    port = self.portEntry.get_text()
                    if port == "":
                        continue
                    proto = self.protoCombo.get_active_text()
                ports = getPortRange(port)
                # check ports
                if not (isinstance(ports, types.ListType) or \
                            isinstance(ports, types.TupleType)):
                    self.dialog(_("Port or port range '%s' is not "
                                  "valid.") % port,
                                _("Please enter a valid port number, service "
                                  "name or range."),
                                type=gtk.MESSAGE_WARNING,
                                center_on=self.portDialog)
                    continue
                self.portDialog.hide()
                return (ports, proto)
            else:
                self.etcServicesView.get_selection().unselect_all()
            break

        self.portDialog.hide()
        return None

    def add_port_cb(self, button, *args):
        result = self.port_selection()
        if result:
            (ports, proto) = result
            if self._portsStoreAppend(ports, proto):
                self.setDirty(True)

    def edit_port_cb(self, button, *args):
        selection = self.otherPortsView.get_selection()
        (model, iter) = selection.get_selected()
        if iter is None:
            return
        port = self.otherPortsStore.get_value(iter, 0)
        proto = self.otherPortsStore.get_value(iter, 1)
        ports = getPortRange(port)

        result = self.port_selection(port, proto)
        if result:
            (_ports, _proto) = result
            if ports != _ports or proto != _proto:
                model.remove(iter) # remove old
                if self._portsStoreAppend(_ports, _proto):
                    self.setDirty(True)

    def _portsStoreAppend(self, ports, proto):
        if len(ports) == 2:
            name1 = getServiceName(ports[0], proto)
            name2 = getServiceName(ports[1], proto)
            _ports = "%d-%d" % (ports[0], ports[1])
            if not name1:
                name1 = ""
            if not name2:
                name2 = ""
            _name = "%s - %s" % (name1, name2)
        else:
            _ports = "%s" % ports[0]
            _name = getServiceName(ports[0], proto)

        iter = self.otherPortsStore.get_iter_first()
        while iter:
            if self.otherPortsStore.get_value(iter, 0) == _ports and \
                    self.otherPortsStore.get_value(iter, 1) == proto:
                # already in list
                return False
            iter = self.otherPortsStore.iter_next(iter)
        self.otherPortsStore.append([_ports, proto, _name])
        return True

    def remove_port_cb(self, button, *args):
        selection = self.otherPortsView.get_selection()
        (model, iter) = selection.get_selected()

        if iter is None:
            return

        model.remove(iter)
        self.setDirty(True)

    def change_custom_combo_cb(self, combo):
        text = self.firewallTableCombo.get_active_text()
        model = self.firewallTableCombo.get_model()
        type = combo.get_active_text()
        model.clear()
        for table in FIREWALL_TABLES:
            if type == "ipv6" and table == "nat":
                continue
            model.append([table])
        self.combobox_select_text(self.firewallTableCombo, text)

    def add_custom_cb(self, button, *args):
        self.customDialog.show_all()
        self.protocolTypeCombo.set_active(0)
        self.firewallTableCombo.set_active(0)
        self.customRulesChooser.unselect_all()
        self.customDialogOkButton.set_sensitive(False)
        result = self.customDialog.run()
        self.customDialog.hide()
        
        if result == gtk.RESPONSE_OK:
            type = self.protocolTypeCombo.get_active_text()
            table = self.firewallTableCombo.get_active_text()
            filename = self.customRulesChooser.get_filename()

            self.setDirty(True)
            self.customStore.append([ type, table, filename ])
 
    def combobox_select_text(self, combobox, value):
        model = combobox.get_model()
        iter = model.get_iter_first()
        while iter:
            if model.get_value(iter, 0) == value:
                combobox.set_active_iter(iter)
                return
            iter = model.iter_next(iter)
        combobox.set_active(0)

    def edit_custom_cb(self, button, *args):
        selection = self.customView.get_selection()
        (model, iter) = selection.get_selected()

        if iter is None:
            return

        _type = self.customStore.get_value(iter, 0)
        _table = self.customStore.get_value(iter, 1)
        _filename = self.customStore.get_value(iter, 2)

        self.customDialog.show_all()
        self.combobox_select_text(self.protocolTypeCombo, _type)
        self.combobox_select_text(self.firewallTableCombo, _table)
        self.customRulesChooser.set_filename(_filename)
        self.customDialogOkButton.set_sensitive(False)
        result = self.customDialog.run()
        self.customDialog.hide()
        
        if result == gtk.RESPONSE_OK:
            type = self.protocolTypeCombo.get_active_text()
            table = self.firewallTableCombo.get_active_text()
            filename = self.customRulesChooser.get_filename()

            if type != _type or table != _table or filename != _filename:
                self.customStore.set_value(iter, 0, type)
                self.customStore.set_value(iter, 1, table)
                self.customStore.set_value(iter, 2, filename)
                self.setDirty(True)

    def remove_custom_cb(self, button, *args):
        selection = self.customView.get_selection()
        (model, iter) = selection.get_selected()

        if iter is None:
            return

        model.remove(iter)
        self.setDirty(True)

    def toggle_port_user_cb(self, check):
        val = check.get_active()
        self.etcServicesSW.set_sensitive(not val)
        self.portUserTable.set_sensitive(val)
        if val:
            self.port_entry_changed_cb(self.portEntry)
        else:
            self.etc_services_selection_cb(self.etcServicesView.get_selection())

    def port_entry_changed_cb(self, entry):
        text = entry.get_text()
        ports = getPortRange(text)
        if not text or not (isinstance(ports, types.ListType) or \
                                isinstance(ports, types.TupleType)):
            self.portDialogOkButton.set_sensitive(False)
        else:
            self.portDialogOkButton.set_sensitive(True)

    def etc_services_selection_ok_cb(self, *args):
        self.portDialogOkButton.clicked()

    def etc_services_selection_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.portDialogOkButton.set_sensitive(True)
        else:
            self.portDialogOkButton.set_sensitive(False)

    def toggle_interface_user_cb(self, check):
        val = check.get_active()
        self.interfaceView.get_parent().set_sensitive(not val)
        self.interfaceEntry.get_parent().set_sensitive(val)
        if val:
            self.interface_entry_changed_cb(self.interfaceEntry)
        else:
            self.interface_selection_cb(self.interfaceView.get_selection())

    def interface_selection_ok_cb(self, *args):
        self.interfaceDialogOkButton.clicked()

    def interface_selection_cb(self, selection):
        (model, iter) = selection.get_selected()
        if iter:
            self.interfaceDialogOkButton.set_sensitive(True)
        else:
            self.interfaceDialogOkButton.set_sensitive(False)

    def interface_entry_changed_cb(self, entry):
        text = entry.get_text()
        if not text or not checkInterface(text):
            self.interfaceDialogOkButton.set_sensitive(False)
        else:
            self.interfaceDialogOkButton.set_sensitive(True)

    def add_interface_cb(self, button, *args):
        interface = self.interface_selection(custom=True)
        if interface:
            self.addInterface(interface)

    def interface_selection(self, interface=None, custom=False):
        self.interfaceView.get_selection().unselect_all()
        self.interfaceUserCheckButton.set_active(False)
        self.interfaceUserCheckButton.set_sensitive(True)
        self.interfaceEntry.set_text("")
        self.interfaceView.expand_all()
        if not interface:
            if custom:
                self.interfaceUserCheckButton.set_active(True)
                self.interfaceUserCheckButton.set_sensitive(False)
            self.interfaceDialogOkButton.set_sensitive(False)
        else:
            iter = self.searchInterface(interface)
            if iter:
                self.interfaceView.get_selection().select_iter(iter)
                self.interfaceView.set_cursor( \
                    self.interfaceStore.get_path(iter))
            else:
                self.interfaceUserCheckButton.set_active(True)
                self.interfaceEntry.set_text(interface)

        self.interfaceDialog.show_all()
        while True:
            result = self.interfaceDialog.run()
            if result == gtk.RESPONSE_OK:
                if not self.interfaceUserCheckButton.get_active():
                    selection = self.interfaceView.get_selection()
                    (model, iter) = selection.get_selected()
                    if not iter:
                        continue
                    interface = model.get(iter, 0)[0]
                else:
                    interface = self.interfaceEntry.get_text()
                    self.addInterface(interface)
                self.interfaceDialog.hide()
                return interface
            else:
                self.interfaceView.get_selection().unselect_all()
            break
        self.interfaceDialog.hide()
        return None

    def add_forward_interface_cb(self, button, *args):
        text = self.forwardInterfaceChooser.get_text()
        if not text or len(text) < 1:
            text = None
        text = self.interface_selection(text)
        if text:
            self.forwardInterfaceChooser.set_text(text)
        self.check_forward_ok()

    def toggle_forward_check_cb(self, check):
        val1 = self.forwardLocalCheckButton.get_active()
        self.forwardFwdAddressLabel.set_sensitive(not val1)
        self.forwardFwdAddressEntry.set_sensitive(not val1)
        self.forwardFwdAddressDescriptionHBox.set_sensitive(not val1)
        self.forwardOtherPortCheckButton.set_sensitive(not val1)
        val2 = self.forwardOtherPortCheckButton.get_active()
        self.forwardFwdPortLabel.set_sensitive(val1 or val2)
        self.forwardFwdPortChooser.set_sensitive(val1 or val2)
        self.check_forward_ok()

    def __set_port(self, label, port):
        if isinstance(port, types.ListType) or \
                isinstance(port, types.TupleType):
            if len(port) == 2:
                ports = "%s-%s" % (port[0], port[1])
            else:
                ports = "%s" % port[0]
        else:
            ports = "%s" % port
        label.set_text(ports)

    def forward_port_selection(self, interface=None, protocol=None, port=None,
                               to_address=None, to_port=None):
        self.forwardDialog.show_all()
        self.forwardInterfaceChooser.reset()
        self.forwardProtocolComboBox.set_active(0)
        self.forwardPortChooser.reset()
        self.forwardLocalCheckButton.set_active(False)
        self.forwardFwdAddressEntry.set_text("")
        self.forwardOtherPortCheckButton.set_active(False)
        self.forwardFwdPortChooser.reset()
        if interface and protocol and port and (to_address or to_port):
            self.forwardInterfaceChooser.set_text(interface)
            self.combobox_select_text(self.forwardProtocolComboBox, protocol)
            self.__set_port(self.forwardPortChooser, port)
            if to_address:
                self.forwardFwdAddressEntry.set_text(to_address)
                if to_port:
                    self.forwardOtherPortCheckButton.set_active(True)
            else:
                # local forward
                self.forwardLocalCheckButton.set_active(True)
            if to_port:
                self.__set_port(self.forwardFwdPortChooser, to_port)
        self.toggle_forward_check_cb(None)

        while True:
            result = self.forwardDialog.run()
            if result == gtk.RESPONSE_OK:
                interface = self.forwardInterfaceChooser.get_text()
                protocol = self.forwardProtocolComboBox.get_active_text()
                port = self.forwardPortChooser.get_text()
                if not interface or not protocol or not port:
                    continue
                to_port = self.forwardFwdPortChooser.get_text()
                if self.forwardLocalCheckButton.get_active():
                    if not to_port:
                        continue
                    to_address = self.fwd_to_local
                else:
                    to_address = self.forwardFwdAddressEntry.get_text()
                    if not to_address or len(to_address) < 1:
                        continue
                    if self.forwardOtherPortCheckButton.get_active():
                        if not to_port:
                            continue
                    else:
                        to_port = None
                self.forwardDialog.hide()
                return (interface, protocol, port, to_address, to_port)
            else:
                self.interfaceView.get_selection().unselect_all()
            break

        self.forwardDialog.hide()
        return None

    def check_forward_ok(self, *args):
        interface = self.forwardInterfaceChooser.get_text()
        protocol = self.forwardProtocolComboBox.get_active_text()
        port = self.forwardPortChooser.get_text()
        to_port = self.forwardFwdPortChooser.get_text()
        to_address = self.forwardFwdAddressEntry.get_text()

        local = self.forwardLocalCheckButton.get_active()
        other = self.forwardOtherPortCheckButton.get_active()

        ok = False
        if interface and protocol and port:
            if local:
                if to_port and to_port != port:
                    ok = True
            else:
                if to_address and len(to_address) > 0 and \
                        checkIP(to_address):
                    if other:
                        if to_port:
                            ok = True
                    else:
                        ok = True

        self.forwardDialogOKButton.set_sensitive(ok)

    def add_forward_port_cb(self, button, label):
        port = label.get_text()
        proto = self.forwardProtocolComboBox.get_active_text()
        result = self.port_selection(port, proto, limit_to_proto=proto)
        if result and len(result) == 2:
            self.__set_port(label, result[0])
        self.check_forward_ok()

    def add_forward_cb(self, button, *args):
        result = self.forward_port_selection()
        if result and len(result) == 5:
            (interface, protocol, port, to_address, to_port) = result
            self.forwardStore.append(result)
            self.setDirty(True)

    def edit_forward_cb(self, button, *args):
        selection = self.forwardView.get_selection()
        (model, iter) = selection.get_selected()

        if iter is None:
            return

        interface = self.forwardStore.get_value(iter, 0)
        protocol = self.forwardStore.get_value(iter, 1)
        port = self.forwardStore.get_value(iter, 2)
        to_address = self.forwardStore.get_value(iter, 3)
        if to_address == "- "+_("local")+" -":
            to_address = None
        to_port = self.forwardStore.get_value(iter, 4)

        result = self.forward_port_selection(interface, protocol, port,
                                             to_address, to_port)
        if result and len(result) == 5:
            (_interface, _protocol, _port, _to_address, _to_port) = result

            if interface != _interface or protocol != _protocol or \
                    port != _port or to_address != _to_address or \
                    to_port != _to_port:
                model.remove(iter)
                if not _to_address:
                    _to_address = self.fwd_to_local
                self.forwardStore.append([_interface, _protocol, _port,
                                          _to_address, _to_port])
                self.setDirty(True)

    def remove_forward_cb(self, button, *args):
        selection = self.forwardView.get_selection()
        (model, iter) = selection.get_selected()

        if iter is None:
            return

        model.remove(iter)
        self.setDirty(True)

    def quit(self, *args):
        if self.dirty:
            result = self.dialog(_("There are unapplied changes, do you "
                                   "really want to quit?"),
                                 type=gtk.MESSAGE_WARNING,
                                 buttons=gtk.BUTTONS_YES_NO)
            if result != gtk.RESPONSE_YES:
                return True
        self.destroy(args)

    def about(self, *args):
        self.aboutDialog.show_all()
        self.aboutDialog.run()
        self.aboutDialog.hide()

    def defaults(self, arg, type=None):
        self.setDefaults(type)
        self.setDirty(True)

    def setDefaults(self, type=None):
        self.clearConfig()

        # set type defaults
        if type != "desktop":
            type = "server"
        iter = self.serviceStore.get_iter_first()
        while iter:
            svc = fw_services.getByName(self.serviceStore.get_value(iter, 1))
            if svc.default and type in svc.default:
                self.serviceStore.set_value(iter, 0, True)
            iter = self.serviceStore.iter_next(iter)

        self.setDirty(True)

    def _findPortInStore(self, port_id, proto):
        str = "%s/%s" % (port_id, proto)
        iter = self.otherPortsStore.get_iter_first()
        while iter:
            if port_id == self.otherPortsStore.get_value(iter, 0) and \
                   proto == self.otherPortsStore.get_value(iter, 1):
                return iter
            else:
                iter = self.otherPortsStore.iter_next(iter)

        return None

    def _setInterfaces(self, store, iter, list, enabled, save, sensitive):
        while iter:
            dev = store.get_value(iter, 0)
            if dev in list:
                list.remove(dev)
                path = store.get_path(iter)
                self.view_toggle_cb(None, path, store, enabled, save, sensitive)
                self.view_sensitive_children_cb(None, path, store, enabled,
                                                save, sensitive)
            iter2 = store.iter_nth_child(iter, 0)
            if iter2:
                self._setInterfaces(store, iter2, list, enabled, save,
                                    sensitive)
            iter = store.iter_next(iter)

    def addInterface(self, device, description=None):
        store = self.interfaceStore
        if not description:
            if device[-1] == "+":
                description = "-- " + _("All %s devices") % device + " --"
            else:
                description = "-- " + _("Not configured") + " --"
        if not self._addInterface(store, store.get_iter_first(), device,
                                  description):
            self.__addDevice(store, None, device, description)
        self.trustedView.expand_all()
        self.masqueradeView.expand_all()
        self.interfaceView.expand_all()

    def _addInterface(self, store, iter, device, description):
        orig_iter = iter
        move = [ ]

        while iter:
            _device = store.get_value(iter, 0)
            if _device == device:
                return True

            if _device[-1] == "+" and device.startswith(_device[:-1]):
                if not self._addInterface(store, store.iter_children(iter),
                                          device, description):
                    # append device to _device
                    self.__addDevice(store, iter, device, description)
                return True
            if device[-1] == "+" and _device.startswith(device[:-1]):
                # reparent _device to device
                move.append(iter)
            iter = store.iter_next(iter)

        if len(move) > 0:
            new_iter = self.__addDevice(store, store.iter_parent(orig_iter),
                                        device, description)
            while len(move) > 0:
                self._moveInterfaceTree(store, move.pop(0), new_iter)

            return True
        return False

    def _moveInterfaceTree(self, store, iter, parent_iter):
        if not iter:
            return
        next_iter = store.iter_next(iter)

        new_parent_iter = store.append(parent_iter, store[store.get_path(iter)])

        _iter = store.iter_children(iter)
        while _iter:
            _iter = self._moveInterfaceTree(store, _iter, new_parent_iter)
            
        store.remove(iter)
        return next_iter

    def __addDevice(self, store, iter, device, description):
        return store.append(iter, [device, description,
                                   False, False, True,
                                   False, False, True])

    def searchInterface(self, device):
        return self._search_interface(self.interfaceStore,
                                      self.interfaceStore.get_iter_first(),
                                      device)
        
    def _search_interface(self, store, iter, device):
        while iter:
            _device = store.get_value(iter, 0)
            if device == _device:
                return iter
            # check children:
            _iter = self._search_interface(store,
                                           store.iter_children(iter),
                                           device)
            if _iter:
                return _iter
            iter = store.iter_next(iter)
        return None

    def loadConfig(self, config):
        self.config = config

        if not config:
            return

        self.clean_config = False

        # enabled / disabled
        if not config.enabled:
            self.firewall_disable()

        # trusted services
        iter =  self.serviceStore.get_iter_first()
        while iter:
            svc = fw_services.getByName(self.serviceStore.get_value(iter, 1))
            if self.config.services and svc.key in self.config.services:
                self.serviceStore.set_value(iter, 0, True)
            iter = self.serviceStore.iter_next(iter)

        # other ports
        if config.ports and len(config.ports) > 0:
            for (ports, proto) in config.ports:
                self._portsStoreAppend(ports, proto)

        # add device if not in list already
        devices = [ ]
        if config.trust:
            devices.extend(config.trust)
        if config.masq:
            devices.extend(config.masq)
        for device in devices:
            self.addInterface(device)

        # trusted devices
        if config.trust:
            # configure trusted interfaces
            self._setInterfaces(self.interfaceStore,
                                self.interfaceStore.get_iter_first(),
                                config.trust,
                                self._if_trust, self._if_trust_save,
                                self._if_trust_sensitive)
        # masquerading
        if config.masq:
            # configure masquerading interfaces
            self._setInterfaces(self.interfaceStore,
                                self.interfaceStore.get_iter_first(),
                                config.masq,
                                self._if_masq, self._if_masq_save,
                                self._if_masq_sensitive)

        self.trustedView.expand_all()
        self.masqueradeView.expand_all()

        # port forwarding
        if config.forward_port:
            for fwd in config.forward_port:
                toaddr = self.fwd_to_local
                toport = None
                if fwd.has_key("toaddr"):
                    toaddr = fwd["toaddr"]
                if len(fwd["port"]) == 1:
                    port = "%s" % fwd["port"][0]
                else:
                    port = "%s-%s" % (fwd["port"][0], fwd["port"][1])
                if fwd.has_key("toport"):
                    if len(fwd["toport"]) == 1:
                        toport = "%s" % fwd["toport"][0]
                    else:
                        toport = "%s-%s" % (fwd["toport"][0],  fwd["toport"][1])
                self.forwardStore.append([ fwd["if"], fwd["proto"],
                                           port, toaddr, toport ])

        # icmp filter
        if self.config.block_icmp and len(self.config.block_icmp) > 0:
            iter = self.icmpStore.get_iter_first()
            while iter:
                icmp = fw_icmp.getByName(self.icmpStore.get_value(iter, 1))
                if icmp.key in self.config.block_icmp:
                    self.icmpStore.set_value(iter, 0, True)
                iter = self.icmpStore.iter_next(iter)

        # custom rules
        if config.custom_rules:
            for entry in config.custom_rules:
                self.customStore.append(entry)

    def dbus_error(self, msg):
        dialog = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR)
        dialog.set_markup("<b>" + _("Error") + "</b>")
        dialog.format_secondary_markup(msg)
        dialog.add_buttons(gtk.STOCK_REDO, gtk.RESPONSE_NO,
                           gtk.STOCK_QUIT, gtk.RESPONSE_CLOSE)
        result = self._dialog(dialog)
        if result != gtk.RESPONSE_NO:
            sys.exit(2)

    def parse_error(self, msg):
        if self.ignore_all:
            return
        dialog = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR)
        dialog.set_markup("<b>" + _("Parse error in config file") + "</b>")
        dialog.format_secondary_markup(msg)
        dialog.add_buttons(_("Ignore"), gtk.RESPONSE_NO,
                           _("Ignore All"), gtk.RESPONSE_YES,
                           gtk.STOCK_QUIT, gtk.RESPONSE_CLOSE)
        result = self._dialog(dialog)
        if result == gtk.RESPONSE_YES:
            self.ignore_all = True
        elif result != gtk.RESPONSE_NO:
            sys.exit(2)
        self.setDirty(True)

    def parse_exit(self, status=0):
        pass

    def readFile(self, *args):
        dirty = False
        self.setDirty(False)
        self.clearConfig()
        self.ignore_all = False

        # load config
        if self.use_dbus:
            try_again = True
            while try_again:
                try:
                    args = self.dbus_proxy.read()
                except Exception, msg:
                    self.dbus_error("%s" % msg)
                else:
                    try_again = False
            if args:
                (args, filename) = args
                config = parse_sysconfig_args(args, filename=filename)
            else:
                config = None
        else:
            config = read_sysconfig_config()

        if self.dirty:
            # parse error
            dirty = True
        if not config:
            # no configuration: defaults are not applied, yet
            self.firewall_disable()
            self.menu_reload.set_sensitive(False)
            self.reloadToolButton.set_sensitive(False)
            self.setDirty(dirty)
            return

        self.loadConfig(config)
        if config.filename:
            self.menu_reload.set_sensitive(True)
            self.reloadToolButton.set_sensitive(True)

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

            self.dialog(_("The firewall configuration is not consistent."),
                        _("The following files are missing or unusable:\n"
                          "\t%s\n\n"
                          "Apply your firewall configuration now to correct "
                          "this problem.") % "\n\t".join(files),
                        type=gtk.MESSAGE_WARNING)
            dirty = True

        if config.converted:
            self.dialog(_("Old firewall configuration."),
                        _("Your firewall configuration was converted from an "
                          "old version. Please verify the configuration and "
                          "apply."))
            dirty = True

        self.setDirty(dirty)

    def _getInterfaces(self, store, iter, list, column):
        while iter:
            dev = store.get_value(iter, 0)
            if store.get_value(iter, column):
                list.append(dev)
            else:
                # walk children:
                iter2 = store.iter_children(iter)
                if iter2:
                    self._getInterfaces(store, iter2, list, column)

            iter = store.iter_next(iter)

    def startWizard(self, *args):
        self.wizardNotebook.set_show_tabs(False)
        self.wizardNotebook.set_current_page(0)
        self.wizardNetworkComboBox.set_active(1)
        self.wizardDefaultsComboBox.set_active(0)
        if self.clean_config:
            self.wizardKeepCheckButton.set_active(False)
            self.wizardKeepCheckButton.set_sensitive(False)
        else:
            self.wizardKeepCheckButton.set_active(True)
            self.wizardKeepCheckButton.set_sensitive(True)
        self.wizardSkillComboBox.set_active(0)
        self.adjust_wizard_buttons()
        self.wizardDialog.show_all()
        while True:
            result = self.wizardDialog.run()
            if result == gtk.RESPONSE_OK:
                # network active?
                if self.wizardNetworkComboBox.get_active() == 0:
                    # no network
                    self.firewall_disable()
                else:
                    self.firewall_enable()
                # cleanup
                if not self.wizardKeepCheckButton.get_active():
                    if self.wizardDefaultsComboBox.get_active_text() == _("Server"):
                        self.setDefaults("server")
                    else:
                        self.setDefaults("desktop")
                    self.setDirty(True)
                hide = [ ]
                # skill level (important: after load defaults)
                if self.wizardSkillComboBox.get_active_text() == _("Beginner"):
                    self.setSkillLevel("beginner")
                else:
                    self.setSkillLevel("expert")
                break
            elif result in [ gtk.RESPONSE_CANCEL, gtk.RESPONSE_DELETE_EVENT ]:
                break
        self.wizardDialog.hide()

    def adjust_wizard_buttons(self):
        i = self.wizardNotebook.get_current_page()
        if i >= 1:
            self.wizardDialogBackButton.set_sensitive(True)
        else:
            self.wizardDialogBackButton.set_sensitive(False)
        if i == self.wizardNotebook.get_n_pages() - 1:
            self.wizardDialogOKButton.set_sensitive(True)
            self.wizardDialogForwardButton.set_sensitive(False)
        elif i < self.wizardNotebook.get_n_pages() - 1:
            self.wizardDialogForwardButton.set_property("visible", True)
            self.wizardDialogForwardButton.set_sensitive(True)
            self.wizardDialogOKButton.set_sensitive(False)
        else:
            self.wizardDialogForwardButton.set_sensitive(False)
        page = self.wizardNotebook.get_nth_page(i)
        name = self.wizardNotebook.get_tab_label_text(page)
        if name == "configuration" and \
                self.wizardNetworkComboBox.get_active() == 0:
            self.wizardDialogOKButton.set_sensitive(True)
            self.wizardDialogForwardButton.set_sensitive(False)

    def wizard_tab_back(self, *args):
        i = self.wizardNotebook.get_current_page() - 1
        self.wizardNotebook.set_current_page(i)
        self.adjust_wizard_buttons()

    def wizard_tab_forward(self, *args):
        i = self.wizardNotebook.get_current_page() + 1
        self.wizardNotebook.set_current_page(i)
        self.adjust_wizard_buttons()

    def change_network_combo_cb(self, *args):
        i = self.wizardNotebook.get_current_page()
        child = self.wizardNotebook.get_nth_page(i)
        name = self.wizardNotebook.get_tab_label_text(child)
        if name == "network" and self.wizardNetworkComboBox.get_active() == 0:
            self.wizardDialogOKButton.set_sensitive(True)
            self.wizardDialogForwardButton.set_sensitive(False)
        else:
            self.wizardDialogOKButton.set_sensitive(False)
            self.wizardDialogForwardButton.set_sensitive(True)

    def settings_toggle_cb(self, toggle, row, model, col):
        iter = model.get_iter(row)
        old_val = model.get(iter, col)[0]
        model.set(iter, col, not old_val)
        self.settingsOKButton.set_sensitive(True)

    def settings(self, *args):
        ipv4_failed = ipv6_failed = False
        # load IPv4 configuration
        ip4tables_conf = fw_iptables.ip4tablesConfig(IP4TABLES_CFG)
        try:
            ip4tables_conf.read()
        except:
            ipv4_failed = True
        # load IPv6 configuration
        ip6tables_conf = fw_iptables.ip6tablesConfig(IP6TABLES_CFG)
        try:
            ip6tables_conf.read()
        except:
            ipv6_failed = True

        # service settings
        self.settingsStore.clear()
        for setting in fw_iptables.setting_list:
            value = ip4tables_conf.get(ip4tables_conf.prefix+setting.key)
            ipv4 = False
            if value == "yes":
                ipv4 = True
            if ipv4_failed:
                ipv4 = setting.iptables
            value = ip6tables_conf.get(ip6tables_conf.prefix+setting.key)
            ipv6 = False
            if value == "yes":
                ipv6 = True
            if ipv6_failed:
                ipv6 = setting.ip6tables
            self.settingsStore.append([setting.key, setting.name, ipv4, ipv6])

        # show dialog
        self.settingsDialog.show_all()
        self.settingsOKButton.set_sensitive(False)
        result = self.settingsDialog.run()
        self.settingsDialog.hide()

        if result == gtk.RESPONSE_OK:
            # store configuration
            iter = self.settingsStore.get_iter_first()
            while iter:
                key = self.settingsStore.get_value(iter, 0)
                if self.settingsStore.get_value(iter, 2):
                    ip4tables_conf.set(ip4tables_conf.prefix+key, "yes")
                else:
                    ip4tables_conf.set(ip4tables_conf.prefix+key, "no")
                if self.settingsStore.get_value(iter, 3):
                    ip6tables_conf.set(ip6tables_conf.prefix+key, "yes")
                else:
                    ip6tables_conf.set(ip6tables_conf.prefix+key, "no")
                iter = self.settingsStore.iter_next(iter)
            # TODO: check status:
            # write IPv4 configuration
            ip4tables_conf.write()
            # write IPv6 configuration
            ip6tables_conf.write()

    def genArgs(self):
        # With the new enabled/disabled behavior, we have to ignore the config
        # file or else you can only ever turn on services.
        args = [ '-f' ]
        # the lokkit command will be added in the apply function if dbus is
        # not in use

        if not self.dirty:
            return 0

        if self.enabled:
            args.append('--enabled')
        else:
            args.append('--disabled')

        trust = [ ]
        iter = self.interfaceStore.get_iter_first()
        self._getInterfaces(self.interfaceStore, iter, trust, self._if_trust)
        for dev in trust:
            args.append("--trust=%s" % dev)

        masquerade = [ ]
        iter = self.interfaceStore.get_iter_first()
        self._getInterfaces(self.interfaceStore, iter, masquerade,
                            self._if_masq)
        for dev in masquerade:
            args.append("--masq=%s" % dev)

        iter = self.serviceStore.get_iter_first()
        while iter:
            svc = fw_services.getByName(self.serviceStore.get_value(iter, 1))
            if self.serviceStore.get_value(iter, 0):
                args.append("--service=%s" % svc.key)
                for module in svc.modules:
                    args.append("--addmodule=%s" % module)
            else:
                if self.config and self.config.services and \
                        svc.key in self.config.services:
                    for module in svc.modules:
                        args.append("--removemodule=%s" % module)

            iter = self.serviceStore.iter_next(iter)

        model = self.otherPortsView.get_model()
        iter = model.get_iter_first()
        while iter:
            port = model.get_value(iter, 0)
            proto = model.get_value(iter, 1)
            args.append("--port=%s:%s" % (port, proto))
            iter = model.iter_next(iter)

        iter = self.forwardStore.get_iter_first()
        while iter:
            interface = self.forwardStore.get_value(iter, 0)
            protocol = self.forwardStore.get_value(iter, 1)
            port = self.forwardStore.get_value(iter, 2)
            to_address = self.forwardStore.get_value(iter, 3)
            to_port = self.forwardStore.get_value(iter, 4)

            line = "--forward-port=if=%s:port=%s:proto=%s" % (interface, port,
                                                              protocol)
            if to_port:
                line += ":toport=%s" % to_port
            if to_address and to_address != self.fwd_to_local:
                line += ":toaddr=%s" % to_address
            args.append(line)

            iter = self.forwardStore.iter_next(iter)

        model = self.icmpView.get_model()
        iter = model.get_iter_first()
        while iter:
            icmp = fw_icmp.getByName(model.get_value(iter, 1))
            if model.get_value(iter, 0):
                args.append("--block-icmp=%s" % icmp.key)
            iter = model.iter_next(iter)

        model = self.customView.get_model()
        iter = model.get_iter_first()
        while iter:
            type = model.get_value(iter, 0)
            table = model.get_value(iter, 1)
            filename = model.get_value(iter, 2)
            args.append("--custom-rules=%s:%s:%s" % (type, table, filename))
            iter = model.iter_next(iter)

        return args

    def apply(self, *args):
        args = self.genArgs()

        result = self.dialog(_("Clicking the 'Yes' button will override "
                               "any existing firewall configuration. "
                               "Are you sure that you want to do this?"),
                             text=_("Please remember to check if the services "
                             "iptables and ip6tables are enabled."),
                             type=gtk.MESSAGE_WARNING,
                             buttons=gtk.BUTTONS_YES_NO)
        if result == gtk.RESPONSE_NO:
            return None

        if not self.use_dbus:
            args.insert(0, '-v')
            args.insert(0, LOKKIT_PROG)

        if self.doDebug:
            print "don't call lokkit if in debug mode"
            print " ".join(args)
        elif self.use_dbus:
            try_again = True
            while try_again:
                try:
                    status = self.dbus_proxy.write(args)
                except Exception, msg:
                    self.dbus_error("%s" % msg)
                else:
                    try_again = False
        else:
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
                self.dialog(_("Configuration failed"),
                            text=cret,
                            type=gtk.MESSAGE_ERROR,
                            buttons=gtk.BUTTONS_CLOSE)

                if not self.config and \
                        os.path.exists(CONFIG) and os.path.isfile(CONFIG):
                    # failed to restart ipXtables, but new config exists
                    self.menu_reload.set_sensitive(True)
                    self.reloadToolButton.set_sensitive(True)
                    
                return 1

        self.readFile()

        return 0

    def resetServices(self):
        iter = self.serviceStore.get_iter_first()
        while iter:
            if self.serviceStore.get_value(iter, 0):
                self.serviceStore.set_value(iter, 0, False)
            iter = self.serviceStore.iter_next(iter)

    def resetICMP(self):
        iter = self.icmpStore.get_iter_first()
        while iter:
            if self.icmpStore.get_value(iter, 0):
                self.icmpStore.set_value(iter, 0, False)
            iter = self.icmpStore.iter_next(iter)

    def resetInterfaces(self):
        self._resetInterfaces(self.interfaceStore,
                              self.interfaceStore.get_iter_first())

    def _resetInterfaces(self, store, iter):
        if not iter:
            return

        while iter:
            store.set(iter, self._if_trust, False, self._if_trust_save, False,
                      self._if_trust_sensitive, True,
                      self._if_masq, False, self._if_masq_save, False,
                      self._if_masq_sensitive, True)

            _iter = store.iter_children(iter)
            while _iter:
                self._resetInterfaces(store, _iter)
                _iter = store.iter_next(_iter)

            iter = store.iter_next(iter)

    def clearConfig(self):
        self.clean_config = True
        self.firewall_enable()
        
        # trusted services
        self.resetServices()

        # other ports
        self.otherPortsStore.clear()

        # interfaces
        self.resetInterfaces()

        self.trustedView.expand_all()
        self.masqueradeView.expand_all()

        # port forwarding
        self.forwardStore.clear()

        # icmp types
        self.resetICMP()

        # custom file
        self.customStore.clear()

        self.setDirty(False)

    def showStartupDialog(self):
        self._dialog(self.startupDialog, timeout=30)

    def dialog(self, message, markup=None, text=None, type=gtk.MESSAGE_INFO,
               buttons=gtk.BUTTONS_OK, center_on=None):
        dialog = gtk.MessageDialog(None, 0, type, buttons)
        dialog.set_markup("<b>" + message + "</b>")
        if text:
            dialog.format_secondary_text(text)
        if markup:
            dialog.format_secondary_markup(markup)
        result = self._dialog(dialog, center_on=center_on)
        dialog.destroy()
        return result

    def _dialog(self, dialog, timeout=0, center_on=None):
        gtk_label_autowrap.set_autowrap(dialog)
        dialog.set_position(gtk.WIN_POS_CENTER_ON_PARENT)
        if center_on:
            dialog.set_transient_for(center_on)
        elif self.mainWindow:
            dialog.set_transient_for(self.mainWindow)
        else:
            dialog.set_position(gtk.WIN_POS_CENTER)
        if not dialog.get_title():
            dialog.set_title(APP_NAME)
        dialog.set_modal(True)
        dialog.set_icon(self.icon)
        dialog.set_keep_above(True)
        dialog.show_all()
        if timeout> 0:
            # hide after timeout seconds
            timer = gobject.timeout_add(timeout*1000, self._hide_dialog, dialog)
        result = dialog.run()
        dialog.hide()
        return result

    def _hide_dialog(self, dialog):
        dialog.hide()
        dialog.destroy()

    def launch(self, doDebug = None):
        self.doDebug = doDebug
        self.setupScreen()

        messageLabel = gtk.Label(_(self.shortMessage))
        messageLabel.set_line_wrap(True)
        messageLabel.set_size_request(500, -1)
        messageLabel.set_alignment(0.0, 0.5)

        self.readFile()
        vbox = gtk.VBox(spacing=10)
        vbox.pack_start(messageLabel, expand=False)
        self.mainVBox.reparent(vbox)

        icon = gtk.Image()
        icon.set_from_pixbuf(self.icon)
        return vbox, icon, self.moduleName

    def run(self):
        self.setupScreen()
        self.mainWindow.connect("delete_event", self.quit)
        self.mainWindow.show()
        # show startup dialog
        self.showStartupDialog()
        # read configuration
        self.readFile()
        gtk.main()
