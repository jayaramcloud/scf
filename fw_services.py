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

from fw_config import _
from fw_functions import getPortID, getServiceName

class _Service:
    def __init__ (self, key, name, ports, description=None, modules=[ ],
                  destination={ }, default=None):
        self.key = key
        self.name = name
        self.ports = ports
        self.description = description
        self.modules = modules
        self.destination = destination
        self.default = default

service_list = [
    _Service("ipp-client", _("Network Printing Client (IPP)"),
             [ ("631", "udp"), ],
             _("The Internet Printing Protocol (IPP) is used for "
               "distributed printing. IPP (over udp) provides the ability to "
               "get information about a printer (e.g. capability and status) "
               "and to control printer jobs. If you plan to use a remote "
               "network printer via cups, do not disable this option."),
             default=["desktop"]),
    _Service("ipp", _("Network Printing Server (IPP)"),
             [ ("631", "tcp"), ("631", "udp"), ],
             _("The Internet Printing Protocol (IPP) is used for "
               "distributed printing. IPP (over tcp) provides the ability to "
               "share printers over the network. Enable this option if you "
               "plan to share printers via cups over the network.")),
    _Service("mdns", _("Multicast DNS (mDNS)"), [ ("5353", "udp"), ],
             _("mDNS provides the ability to use DNS programming "
               "interfaces, packet formats and operating semantics in a "
               "small network without a conventional DNS server. If you plan "
               "to use Avahi, do not disable this option."),
             default=["desktop"],
             destination={"ipv4": "224.0.0.251", "ipv6": "ff02::fb"}),
    _Service("ipsec", _("IPsec"), [ (None, "ah"), (None, "esp"), 
                                    (500, "udp"), ],
             _("Internet Protocol Security (IPsec) incorporates security "
               "for network transmissions directly into the Internet Protocol "
               "(IP). IPsec provides methods for both encrypting data "
               "and authentication for the host or network it sends to. If you "
               "plan to use a vpnc server or FreeS/WAN, do not disable this "
               "option."),
             default=["desktop"]),

    _Service("ssh", _("SSH"), [ ("22", "tcp"), ],
             _("Secure Shell (SSH) is a protocol for logging into and "
               "executing commands on remote machines. It provides secure "
               "encrypted communications. If you plan on accessing your "
               "machine remotely via SSH over a firewalled interface, enable "
               "this option. You need the openssh-server package installed "
               "for this option to be useful." ),
             default=["server"]),
#    _Service("telnet", _("Telnet"), [ ("23", "tcp"), ],
#             "Telnet is a protocol for logging into remote machines. It "
#             "is unencrypted, and provides little security from network "
#             "snooping attacks. Enabling telnet is not recommended. You need "
#             "the telnet-server package installed for this option to be "
#             "useful."),
    _Service("http", _("WWW (HTTP)"), [ ("80", "tcp"), ],
             _("HTTP is the protocol used to serve Web pages. If you plan to "
               "make your Web server publicly available, enable this option. "
               "This option is not required for viewing pages locally or "
               "developing Web pages.")),
    _Service("ftp", _("FTP"), [ ("21", "tcp"), ],
             _("FTP is a protocol used for remote file transfer. If you plan "
               "to make your FTP server publicly available, enable this "
               "option. You need the vsftpd package installed for this option "
               "to be useful."),
             modules=[ "nf_conntrack_ftp", ]),
    _Service("nfs", _("NFS4"), [ ("2049", "tcp"), ],
             _("The NFS4 protocol is used to share files via TCP networking. "
               "You will need to have the NFS tools installed "
               "and properly configure your NFS server for this option to be "
               "useful.")),
    _Service("https", _("Secure WWW (HTTPS)"), [ ("443", "tcp"), ],
             _("HTTPS is a modified HTTP used to serve Web pages when security "
               "is important. Examples are sites that require logins like "
               "stores or web mail. This option is not required for viewing "
               "pages locally or developing Web pages. You need the httpd "
               "package installed for this option to be useful.")),
    _Service("smtp", _("Mail (SMTP)"), [ ("25", "tcp"), ],
             _("This option allows incoming SMTP mail delivery. If you need "
               "to allow "
               "remote hosts to connect directly to your machine to deliver "
               "mail, enable this option. You do not need to enable this if "
               "you collect your mail from your ISP's server by POP3 or IMAP, "
               "or if you use a tool such as fetchmail. Note that an "
               "improperly configured SMTP server can allow remote machines "
               "to use your server to send spam.")),
    _Service("samba-client", _("Samba Client"), [ ("137", "udp"),
                                                  ("138", "udp"), ],
             _("This option allows you to access Windows file and printer "
               "sharing networks. You need the samba-client "
               "package installed for this option to be useful."),
             modules=[ "nf_conntrack_netbios_ns", ],
             default=["desktop"]),
    _Service("samba", _("Samba"), [ ("137", "udp"), ("138", "udp"),
                                    ("139", "tcp"), ("445", "tcp"), ],
             _("This option allows you to access and participate in Windows "
               "file and printer sharing networks. You need the samba "
               "package installed for this option to be useful."),
             modules=[ "nf_conntrack_netbios_ns", ]),
    _Service("dns", _("DNS"), [ ("53", "tcp"), ("53", "udp"), ],
             _("The Domain Name System (DNS) is used to provide and request "
               "host and domain names. Enable this option, if you plan to "
               "provide a domain name service (e.g. with bind).")),
    _Service("imaps", _("IMAP over SSL"), [ ("993", "tcp"), ],
             _("The Internet Message Access Protocol over SSL (IMAPs) allows "
               "a local client to access email on a remote server in a secure "
               "way. If you plan to provide a IMAP over SSL service (e.g. with "
               "dovecot), enable this option.")),
    _Service("pop3s", _("POP-3 over SSL"), [ ("995", "tcp"), ],
             _("The Post Office Protocol version 3 (POP3) is a protocol to "
               "retrieve email from a remote server over a TCP/IP "
               "connection. Enable this option, if you plan to provide a POP3 "
               "service (e.g. with dovecot).")),
    _Service("radius", _("RADIUS"), [ ("1812", "udp"), ("1813", "udp"), ],
             _("The Remote Authentication Dial In User Service (RADIUS) is a "
               "protocol for user authentication over networks. It is mostly "
               "used for modem, DSL or wireless user authentication. If you "
               "plan to provide a RADIUS service (e.g. with freeradius), "
               "enable this option.")),
    _Service("openvpn", _("OpenVPN"), [ ("1194", "udp"), ],
             _("OpenVPN is a virtual private network (VPN) solution. It is "
               "used to create encrypted point-to-point tunnels between "
               "computers. If you plan to provide a VPN service, enable this "
               "option.")),
    _Service("tftp", _("TFTP"), [ ("69", "udp"), ],
             _("The Trivial File Transfer Protocol (TFTP) is a protocol used "
               "to transfer files to and from a remote machine in s simple "
               "way. It is normally used only for booting diskless "
               "workstations and also to transfer data in the Preboot "
               "eXecution Environment (PXE)."),
             modules=[ "nf_conntrack_tftp", ]),
    _Service("tftp-client", _("TFTP Client"), [ ],
             _("This option allows you to access Trivial File Transfer "
               "Protocol (TFTP) servers. You need the tftp "
               "package installed for this option to be useful."),
             modules=[ "nf_conntrack_tftp", ]),

    _Service("cluster-suite", _("Red Hat Cluster Suite"), [
            # corosync/openais
            (5404, "udp"), (5405, "udp"),
            # rgmanager pre F-12, RHEL-6
            #(41966, "tcp"), (41967, "tcp"), (41968, "tcp"), (41969, "tcp"),
            # ricci
            (11111, "tcp"),
            # dlm
            (21064, "tcp"),
            # cssd pre F-12, RHEL-6
            #(50006, "tcp"), (50008, "tcp"), (50009, "tcp"), (50007, "udp"),
            ],
             _("This option allows you to use the Red Hat Cluster Suite. "
               "Ports are opened for openais, ricci and dlm. You need the "
               "Red Hat Cluster Suite installed for this option to be "
               "useful.")),

    _Service("amanda-client", _("Amanda Backup Client"), [ (10080, "udp"), ],
             _("The Amanda backup client option allows you to connect to a "
               "Amanda backup and archiving server. You need the "
               "amanda-client package installed for this option to be "
               "useful."),
             modules=[ "nf_conntrack_amanda", ]),

    _Service("bacula-client", _("Bacula Client"),  [ (9102, "tcp"), ],
             _("This option allows a Bacula server to connect to the local "
               "machine to schedule backups. You need the bacula-client "
               "package installed for this option to be useful.")),
    _Service("bacula", _("Bacula"),  [ (9101, "tcp"), (9102, "tcp"),
                                       (9103, "tcp"), ],
             _("Bacula is a network backup solution. Enable this option, if "
               "you plan to provide Bacula backup, file and storage "
               "services.")),

    _Service("libvirt", _("Virtual Machine Management"),  [ (16509, "tcp"), ],
             _("Enable this option if you want to allow remote virtual "
               "machine management with SASL authentication and encryption "
               "(digest-md5 passwords or GSSAPI/Kerberos). The libvirtd "
               "service is needed for this option to be useful.")),

    _Service("libvirt-tls", _("Virtual Machine Management (TLS)"), 
             [ (16514, "tcp"), ],
             _("Enable this option if you want to allow remote virtual "
               "machine management with TLS encryption, x509 certificates "
               "and optional SASL authentication. The libvirtd service is "
               "needed for this option to be useful.")),
    ]

def getByKey(key):
    for x in service_list:
        if x.key == key:
            return x
    return None

def getByName(name):
    for x in service_list:
        if x.name == name:
            return x
    return None

def getByPort(port, proto):
    for x in service_list:
        id = getPortID(port)
        name = getServiceName(port, proto)
        if (id, proto) in x.ports or (str(id), proto) in x.ports or \
               (name, proto) in x.ports:
            return x
    return None        
