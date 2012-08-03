#!/usr/bin/python
#
# Copyright (C) 2008 Red Hat, Inc.
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Florian Festi <ffesti@redhat.com>
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

class ChooserButton:
    def __init__(self, button, default_label=""):
        self.button = button
        self.default_label = default_label

        self.label = None
        self._menu = None
        self._icon = None

        children = self.button.get_children()
        if len(children) == 1 and type(children[0]) == gtk.HBox:
            children = children[0].get_children()
            for child in children:
                if type(child) == gtk.Label:
                    self.label = child
                    break
        else:
            for child in list(button.get_children()):
                button.remove(child)
            hbox = gtk.HBox()
            self.label = gtk.Label()
            arrow = gtk.Arrow(gtk.ARROW_DOWN, gtk.SHADOW_IN)
            hbox.set_spacing(2)
            hbox.pack_start(self.label)
            hbox.pack_end(arrow, expand=False)
            button.add(hbox)
        if not self.label:
            raise ValueError, "%s is not a ChooserButton" % button.get_name()
        self.connect("clicked", self._show_menu)
        self.reset()

    def set_sensitive(self, value):
        self.button.set_sensitive(value)

    def connect(self, type, *args):
        self.button.connect(type, *args)

    def get_text(self):
        return self.text

    def set_text(self, text):
        if not text or len(text) < 1:
            self.reset()
        self.text = text
        self.label.set_text(self.text)

    def set_stock_icon(self, name, size=gtk.ICON_SIZE_MENU):
        if self._icon is None:
            self._icon = gtk.Image()
            hbox = self.button.get_child()
            hbox.pack_start(self._icon)
            hbox.reorder_child(self._icon, 0)
            
        self._icon.set_from_stock(name, size)

    def reset(self):
        self.text = None
        self.label.set_text(self.default_label)

    def set_menu(self, menu):
        self._menu = menu
        if menu:
            menu.attach_to_widget(self.button, self._detach_menu)

    def get_menu(self):
        return self._menu

    def _detach_menu(self):
        self._menu = None

    def _show_menu(self, *args):
        if not self._menu:
            return
        self._menu.popup(None, None, self._menu_position_func, 0, 0)

    def _menu_position_func(self, menu):
        allocation = self.button.get_allocation()
        (menu_width, menu_height) = menu.size_request()
        if menu_width != allocation.width:
            menu.set_size_request(-1, -1)
            (_width, _height) = menu.size_request()
            if _width > allocation.width:
                menu.set_size_request(_width, _height)
            else:
                menu.set_size_request(allocation.width, -1)

        (x, y) = self.button.get_parent_window().get_origin()
        x += allocation.x
        y += allocation.y + allocation.height

        root = self.button.get_root_window()
        (root_x, root_y, root_width, root_height, root_depth) = \
            self.button.get_root_window().get_geometry()

        if y + menu_height > root_height:
            y -= menu_height + allocation.height

        return (x, y, True)


class ToolChooserButton:
    
    def __init__(self, button, default_label=''):
        
        self.button = button
        self.default_label = default_label

        self._menu = None
        self._icon = None

        self.reset()

        self.set_sensitive = self.button.set_sensitive

    def get_text(self):
        return self.text

    def set_text(self, text):
        if not text or len(text) < 1:
            self.reset()
        self.text = text
        self.button.set_label(text)

    def set_stock_icon(self, name, size=gtk.ICON_SIZE_BUTTON):
        if self._icon is None:
            self._icon = gtk.Image()
            self.button.set_icon_widget(self._icon)

        self._icon.set_from_stock(name, size)

    def reset(self):
        self.text = None
        self.button.set_label(self.default_label)

    def set_menu(self, menu):
        self._menu = menu
        self.button.set_menu(menu)

    def get_menu(self):
        return self._menu

    def _detach_menu(self):
        self._menu = None

##############################################################################

if __name__ == "__main__":
    window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    window.connect("delete_event", gtk.main_quit)

    button = gtk.Button("ChooserButton")
    chooserbutton = ChooserButton(button, "Enabled")

    hbox = gtk.HBox()
    hbox.pack_start(button)
    window.add(hbox)

    menu = gtk.Menu()
    for i in xrange(10):
        item = gtk.CheckMenuItem("level %d" % i)
#        item = gtk.MenuItem("level %d" % i)
        menu.add(item)
    menu.show_all()

    chooserbutton.set_menu(menu)

    window.show_all()
    gtk.main()
