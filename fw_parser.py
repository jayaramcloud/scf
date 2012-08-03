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

from copy import copy
from optparse import Option, OptionError, OptionParser, Values, \
    SUPPRESS_HELP, BadOptionError, OptionGroup
import fw_config
from fw_functions import getPortID, getPortRange, getServiceName, checkIP, \
    checkInterface
from fw_services import getByKey as getServiceByKey
from fw_icmp import getByKey as getICMPTypeByKey
import os.path
import sys

def _check_port(option, opt, value):
    failure = False
    try:
        (ports, protocol) = value.split(":")
    except:
        failure = True
    else:
        range = getPortRange(ports.strip())
        if range == -1:
            failure = True
        elif range == None:
            raise OptionError(_("port range %s is not unique.") % value, opt)
        elif len(range) == 2 and range[0] >= range[1]:
            raise OptionError(_("%s is not a valid range (start port >= end "
                                "port).") % value, opt)
    if not failure:
        protocol = protocol.strip()
        if protocol not in [ "tcp", "udp" ]:
            raise OptionError(_("%s is not a valid protocol.") % protocol, opt)
    if failure:
        raise OptionError(_("invalid port definition %s.") % value, opt)
    return (range, protocol)

def _check_rulesfile(option, opt, value):
    type = "ipv4"
    table = "filter"
    splits = value.split(":", 1)
    if len(splits) > 1 and splits[0] in fw_config.FIREWALL_TYPES:
        type = splits[0]
        splits = splits[1].split(":", 1)
    if len(splits) > 1 and splits[0] in fw_config.FIREWALL_TABLES:
        table = splits[0]
        splits = splits[1].split(":", 1)
    filename = ":".join(splits)

    if type == "ipv6" and table == "nat":
        raise OptionError(_("ipv6 has no nat support."), opt)

    return (type, table, filename)

def _check_service(option, opt, value):
    if not getServiceByKey(value):
        raise OptionError(_("invalid service '%s'.") % value, opt)
    return value

def _check_icmp_type(option, opt, value):
    if not getICMPTypeByKey(value):
        dict = { "option": opt, "value": value }
        raise OptionError(_("option %(option)s: invalid icmp type "
                                 "'%(value)s'.") % dict, opt)
    return value

def _check_forward_port(option, opt, value):
    result = { }
    error = None
    splits = value.split(":", 1)
    while len(splits) > 0:
        key_val = splits[0].split("=")
        if len(key_val) != 2:
            error = _("Invalid argument %s") % splits[0]
            break
        (key, val) = key_val
        if (key == "if" and checkInterface(val)) or \
                (key == "proto" and val in [ "tcp", "udp" ]) or \
                (key == "toaddr" and checkIP(val)):
            result[key] = val
        elif (key == "port" or key == "toport") and getPortRange(val) > 0:
            result[key] = getPortRange(val)
        else:
            error = _("Invalid argument %s") % splits[0]
            break
        if len(splits) > 1:
            if splits[1].count("=") == 1:
                # last element
                splits = [ splits[1] ]
            else:
                splits = splits[1].split(":", 1)
        else:
            # finish
            splits.pop()

    if error:
        dict = { "option": opt, "value": value, "error": error }
        raise OptionError(_("option %(option)s: invalid forward_port "
                                 "'%(value)s': %(error)s.") % dict, opt)

    error = False
    for key in [ "if", "port", "proto" ]:
        if key not in result.keys():
            error = True
    if not "toport" in result.keys() and not "toaddr" in result.keys():
        error = True
    if error:
        dict = { "option": opt, "value": value }
        raise OptionError(_("option %(option)s: invalid forward_port "
                                 "'%(value)s'.") % dict, opt)

    return result

def _check_interface(option, opt, value):
    if not checkInterface(value):
        raise OptionError(_("invalid interface '%s'.") % value, opt)
    return value

def _append_unique(option, opt, value, parser, *args, **kwargs):
    vals = getattr(parser.values, option.dest)
    if vals and value in vals:
        return
    parser.values.ensure_value(option.dest, []).append(value)

class _Option(Option):
    TYPES = Option.TYPES + ("port", "rulesfile", "service", "forward_port",
                            "icmp_type", "interface")
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["port"] = _check_port
    TYPE_CHECKER["rulesfile"] = _check_rulesfile
    TYPE_CHECKER["service"] = _check_service
    TYPE_CHECKER["forward_port"] = _check_forward_port
    TYPE_CHECKER["icmp_type"] = _check_icmp_type
    TYPE_CHECKER["interface"] = _check_interface

def _addStandardOptions(parser):
    parser.add_option("--enabled",
                      action="store_true", dest="enabled", default=True,
                      help=_("Enable firewall (default)"))
    parser.add_option("--disabled",
                      action="store_false", dest="enabled",
                      help=_("Disable firewall"))
    parser.add_option("--addmodule",
                      action="callback", dest="add_module", type="string",
                      metavar=_("<module>"),  callback=_append_unique,
                      help=_("Enable an iptables module"))
    parser.add_option("--removemodule",
                      action="callback", dest="remove_module", type="string",
                      metavar=_("<module>"), callback=_append_unique,
                      help=_("Disable an iptables module"))
    parser.add_option("-s", "--service",
                      action="callback", dest="services", type="service",
                      default=[ ],
                      metavar=_("<service>"), callback=_append_unique,
                      help=_("Open the firewall for a service (e.g, ssh)"))
    parser.add_option("-p", "--port",
                      action="callback", dest="ports", type="port",
                      metavar=_("<port>[-<port>]:<protocol>"),
                      callback=_append_unique,
                      help=_("Open specific ports in the firewall "
                             "(e.g, ssh:tcp)"))
    parser.add_option("-t", "--trust",
                      action="callback", dest="trust", type="interface",
                      metavar=_("<interface>"), callback=_append_unique,
                      help=_("Allow all traffic on the specified device"))
    parser.add_option("-m", "--masq",
                      action="callback", dest="masq", type="interface",
                      metavar=_("<interface>"), callback=_append_unique,
                      help=_("Masquerades traffic from the specified device. "
                             "This is IPv4 only."))
    parser.add_option( "--high", "--medium",
                      action="store_true", dest="enabled",
                      help=_("Backwards compatibility, aliased to --enabled"))
    parser.add_option("--custom-rules",
                      action="callback", dest="custom_rules", type="rulesfile",
                      metavar=_("[<type>:][<table>:]<filename>"),
                      callback=_append_unique,
                      help=_("Specify a custom rules file for inclusion in "
                             "the firewall, after the "
                             "default rules. Default protocol type: ipv4, "
                             "default table: filter. "
                             "(Example: ipv4:filter:/etc/sysconfig/"
                             "ipv4_filter_addon)"))
    parser.add_option("--forward-port",
                      action="callback", dest="forward_port",
                      type="forward_port",
                      metavar=_("if=<interface>:port=<port>:proto=<protocol>"
                                "[:toport=<destination port>]"
                                "[:toaddr=<destination address>]"),
                      callback=_append_unique,
                      help=_("Forward the port with protocol for the "
                             "interface to either another local destination "
                             "port (no destination address given) or to an "
                             "other destination address with an optional "
                             "destination port. This is IPv4 only."))
    parser.add_option("--block-icmp",
                      action="callback", dest="block_icmp", type="icmp_type",
                      default=[ ],
                      callback=_append_unique,
                      metavar=_("<icmp type>"),
                      help=_("Block this ICMP type. The default is to accept "
                             "all ICMP types."))

def _addCompatOptions(parser):
    parser.add_option("--no-ipsec",
                      action="store_true", dest="no_ipsec",
                      help=_("Disable Internet Protocol Security (IPsec)"))
    parser.add_option("--no-ipp",
                      action="store_true", dest="no_ipp",
                      help=_("Disable Internet Printing Protocol (IPP)"))
    parser.add_option("--no-mdns",
                      action="store_true", dest="no_mdns",
                      help=_("Disable Multicast DNS (mDNS)"))

def _addSELinuxOptions(parser):
    group = OptionGroup(parser, _("SELinux Options (deprecated)"),
                        _("Using these options with no additional firewall "
                          "options will not create or alter firewall "
                          "configuration, only SELinux will be configured."))

    group.add_option("--selinux",
                      action="store", dest="selinux", type="choice",
                      metavar=_("<mode>"), choices=fw_config.SELINUX_MODES,
                      help=_("Configure SELinux mode: %s") % \
                          ", ".join(fw_config.SELINUX_MODES))
    group.add_option("--selinuxtype",
                      action="store", dest="selinuxtype", type="string",
                      metavar=_("<type>"),
                      help=_("Configure SELinux type: Usually targeted or "
                             "strict Policy"))

    parser.add_option_group(group)

def _parse_args(parser, args, options=None):
    try:
        (_options, _args) = parser.parse_args(args, options)
    except Exception, error:
        parser.error(error)
        return None

    if len(_args) != 0:
        for arg in _args:
            parser.error(_("no such option: %s") % arg)
    if parser._fw_exit:
        if fw_config.ui:
            fw_config.ui.parse_exit(2)
        else:
            sys.exit(2)
    if not hasattr(_options, "filename"):
        _options.filename = None
    if not hasattr(_options, "converted"):
        _options.converted = False
    return _options

class _OptionParser(OptionParser):
    # overload print_help: rhpl._ returns UTF-8
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout

        str = self.format_help()
        if isinstance(str, unicode):
            encoding = self._get_encoding(file)
            str = str.encode(encoding, "replace")
        file.write(str)
    def print_usage(self, file=None):
        pass
    def exit(self, status=0, msg=None):
        if msg:
            if fw_config.ui:
                fw_config.ui.parse_error(msg)
            else:
                print >>sys.stderr, msg
        if not fw_config.ui:
            self._fw_exit = True
    def error(self, msg):
        if self._fw_source:
            text = "%s: %s" % (self._fw_source, msg)
        else:
            text = str(msg)
        self.exit(2, msg=text)
    def _match_long_opt(self, opt):
        if self._long_opt.has_key(opt):
            return opt
        raise BadOptionError(opt)
    def _process_long_opt(self, rargs, values):
        # allow to ignore errors in the ui
        try:
#            OptionParser._process_long_opt(self, rargs, values)
            self.__process_long_opt(rargs, values)
        except Exception, msg:
            self.error(msg)
    def _process_short_opts(self, rargs, values):
        # allow to ignore errors in the ui
        try:
            OptionParser._process_short_opts(self, rargs, values)
        except Exception, msg:
            self.error(msg)
    def __process_long_opt(self, rargs, values):
        arg = rargs.pop(0)

        # Value explicitly attached to arg?  Pretend it's the next
        # argument.
        if "=" in arg:
            (opt, next_arg) = arg.split("=", 1)
            had_explicit_value = True
        else:
            opt = arg
            had_explicit_value = False

        opt = self._match_long_opt(opt)
        option = self._long_opt[opt]
        if option.takes_value():
            nargs = option.nargs
            if len(rargs)+int(had_explicit_value) < nargs:
                if nargs == 1:
                    self.error(_("%s option requires an argument") % opt)
                else:
                    dict = { "option": opt, "count": nargs }
                    self.error(_("%(option)s option requires %(count)s "
                                 "arguments") % dict)
            elif nargs == 1 and had_explicit_value:
                value = next_arg
            elif nargs == 1:
                value = rargs.pop(0)
            elif had_explicit_value:
                value = tuple([ next_arg ] + rargs[0:nargs-1])
                del rargs[0:nargs-1]
            else:
                value = tuple(rargs[0:nargs])
                del rargs[0:nargs]

        elif had_explicit_value:
            self.error(_("%s option does not take a value") % opt)

        else:
            value = None

        option.process(opt, value, values, self)

def _gen_parser(source=None):
    parser = _OptionParser(add_help_option=False, option_class=_Option)
    parser._fw_source = source
    parser._fw_exit = False
    return parser

def parseSysconfigArgs(args, options=None, compat=False, source=None):
    parser = _gen_parser(source)
    _addStandardOptions(parser)
    if compat:
        _addCompatOptions(parser)
    return _parse_args(parser, args, options)

def parseSELinuxArgs(args, options=None, source=None):
    parser = _gen_parser(source)
    _addSELinuxOptions(parser)
    return _parse_args(parser, args, options)

def parseLokkitArgs(args=None, options=None, compat=False):
    parser = _gen_parser()
    parser.add_option("-?", "-h", "--help", "--usage", action="help",
                      help=_("Show this help message"))
    parser.add_option("-q", "--quiet",
                      action="store_true", dest="quiet",
                      help=_("Run noninteractively; process only command-line "
                             "arguments"))
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose",
                      help=_("Be more verbose"))
    parser.add_option("--version",
                      action="store_true", dest="version",
                      help=_("Show version"))
    parser.add_option("-n", "--nostart",
                      action="store_true", dest="nostart",
                      help=_("Configure firewall but do not activate the new "
                             "configuration"))
    parser.add_option("-f",
                      action="store_true", dest="force",
                      help=_("Ignore actual settings"))
    parser.add_option("--update",
                      action="store_true", dest="update",
                      help=_("Update firewall non-interactively if the "
                             "firewall is enabled. This will also restart the "
                             "firewall. The -n and -f options will be "
                             "ignored."))
    parser.add_option("--default",
                      action="store", dest="default", type="choice",
                      metavar=_("<type>"), choices=fw_config.DEFAULT_TYPES,
                      help=_("Set firewall default type: %s. "
                             "This overwrites any existing "
                             "configuration.") % ", ".join(fw_config.DEFAULT_TYPES))
    parser.add_option("--list-services",
                      action="store_true", dest="list_services",
                      help=_("List predefined services."))
    parser.add_option("--list-icmp-types",
                      action="store_true", dest="list_icmp_types",
                      help=_("List the supported icmp types."))
    _addSELinuxOptions(parser)
    _addStandardOptions(parser)

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    _options = _parse_args(parser, args, options)

    _options.nofw = False
    if args == None and _options:
        selinux = False
        firewall = False
        for arg in sys.argv[1:]:
            if arg.startswith("--selinux"):
                selinux = True
            else:
                firewall = True
        if selinux and not firewall:
            _options.nofw = True

    return _options

def parseDBUSArgs(args=None, options=None, compat=False):
    parser = _gen_parser()
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="verbose",
                      help=_("Be more verbose"))
    parser.add_option("-n", "--nostart",
                      action="store_true", dest="nostart",
                      help=_("Configure firewall but do not activate the new "
                             "configuration"))
    parser.add_option("-f",
                      action="store_true", dest="force",
                      help=_("Ignore actual settings"))
    parser.add_option("--update",
                      action="store_true", dest="update",
                      help=_("Update firewall non-interactively if the "
                             "firewall is enabled. This will also restart the "
                             "firewall. The -n and -f options will be "
                             "ignored."))
    parser.add_option("--default",
                      action="store", dest="default", type="choice",
                      metavar=_("<type>"), choices=fw_config.DEFAULT_TYPES,
                      help=_("Set firewall default type: %s. "
                             "This overwrites any existing "
                             "configuration.") % ", ".join(fw_config.DEFAULT_TYPES))
    _addSELinuxOptions(parser)
    _addStandardOptions(parser)

    return _parse_args(parser, args, options)

def copyValues(values):
    if not values:
        return None
    new_values = Values()
    new_values.__dict__ = copy(values.__dict__)
    return new_values
