#!/usr/bin/python

import sys

NM_DBUS_PATH                    = "/org/freedesktop/NetworkManager"
NM_DBUS_INTERFACE               = "org.freedesktop.NetworkManager"
NM_DBUS_SERVICE_SYSTEM_SETTINGS = "org.freedesktop.NetworkManagerSystemSettings"
NM_DBUS_SERVICE_USER_SETTINGS   = "org.freedesktop.NetworkManagerUserSettings"
NM_DBUS_IFACE_DEVICE            = "org.freedesktop.NetworkManager.Device"
NM_DBUS_IFACE_DEVICE_WIRED      = "org.freedesktop.NetworkManager.Device.Wired"
NM_DBUS_IFACE_DEVICE_WIRELESS   = "org.freedesktop.NetworkManager.Device.Wireless"

NM_DEVICE_TYPE_UNKNOWN = 0
NM_DEVICE_TYPE_ETHERNET = 1
NM_DEVICE_TYPE_WIFI = 2
NM_DEVICE_TYPE_GSM = 3
NM_DEVICE_TYPE_CDMA = 4

nm_device_type = {
      NM_DEVICE_TYPE_UNKNOWN: "unknown type",
      NM_DEVICE_TYPE_ETHERNET: "wired Ethernet",
      NM_DEVICE_TYPE_WIFI: "802.11 WiFi",
      NM_DEVICE_TYPE_GSM: "GSM-based cellular WAN",
      NM_DEVICE_TYPE_CDMA: "CDMA/IS-95-based cellular WAN"
}

#####

import dbus
bus = dbus.SystemBus()

def device_list():
      devices = { }

      for service in [ NM_DBUS_SERVICE_SYSTEM_SETTINGS,
                       NM_DBUS_SERVICE_USER_SETTINGS ]:

            proxy = bus.get_object(service, NM_DBUS_PATH)
            iface = dbus.Interface(proxy, dbus_interface=NM_DBUS_INTERFACE)
            try:
                  device_list = iface.GetDevices()
            except:
                  continue

            for c in device_list:
                  proxy = bus.get_object(service, c)
                  properties = dbus.Interface(proxy, dbus_interface='org.freedesktop.DBus.Properties')

                  interface = properties.Get(NM_DBUS_IFACE_DEVICE, 'Interface')
                  device_type = properties.Get(NM_DBUS_IFACE_DEVICE,
                                               'DeviceType')
                  if device_type == NM_DEVICE_TYPE_ETHERNET:
                        hwaddr = properties.Get(NM_DBUS_IFACE_DEVICE_WIRED,
                                                'HwAddress')
                  elif device_type == NM_DEVICE_TYPE_WIFI:
                        hwaddr = properties.Get(NM_DBUS_IFACE_DEVICE_WIRELESS,
                                                'HwAddress')
                  else:
                        continue

                  devices[str(interface)] = {
                        "type": nm_device_type[device_type],
                        "hwaddr": str(hwaddr),
                        }
      return devices
