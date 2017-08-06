import struct
from ipaddress import IPv6Address

from .icmp import ICMP, ICMPData, ICMPEchoRequest, ICMPEchoReply
from .common import ICMPv6Type, ICMPv6TypeCodeMap
from .common import checksum as csum
from ..exceptions import *

'''
References:
    http://tools.ietf.org/html/rfc4443
    Stevens, Fall, TCP/IP Illustrated, Vol 1., 2nd Ed.
    https://notes.shichao.io/tcpv1/ch8/
'''


class ICMPv6(ICMP):
    def __init__(self, **kwargs):
        # Another hacky way to make this thing work.. super should be last..
        self.icmp6type = kwargs['icmptype']
        del kwargs['icmptype']
        super().__init__(**kwargs)
        kwargs['icmptype'] = self.icmp6type
        
        self._valid_types = ICMPv6Type
        self._valid_codes_map = ICMPv6TypeCodeMap
        self._classtype_from_icmptype = ICMPv6ClassFromType
        self._icmptype_from_classtype = ICMPv6TypeFromClass
        self._type = self._valid_types.EchoRequest
        self._code = self._valid_codes_map[self._type].EchoRequest
        self._icmpdata = ICMPv6ClassFromType(self._type)()
        self._checksum = 0
        # if kwargs are given, must ensure that type gets set
        # before code due to dependencies on validity.
        if 'icmptype' in kwargs:
            self.icmptype = kwargs['icmptype']
            # del kwargs['icmptype']

    def checksum(self):
        return self._checksum

    def _compute_checksum(self, src, dst, raw):
        sep = b''
        databytes = self._icmpdata.to_bytes()
        icmpsize = ICMP._MINLEN+len(databytes)
        self._checksum = csum(sep.join( (src.packed, dst.packed,
            struct.pack('!I3xBBB', 
                ICMP._MINLEN+len(databytes), 58, self._type.value, self._code.value), 
            databytes) ))

    def pre_serialize(self, raw, pkt, i):
        ip6hdr = pkt.get_header('IPv6')
        assert(ip6hdr is not None)
        self._compute_checksum(ip6hdr.src, ip6hdr.dst, raw)

class ICMPv6Data(ICMPData):
    '''Hack to make the inheritance chain happy and lead into v6 specific differences'''
    pass

class ICMPv6Options(ICMPv6Data):
    pass

class ICMPv6EchoRequest(ICMPEchoRequest):
    pass

class ICMPv6EchoReply(ICMPEchoReply):
    pass
  

class ICMPv6HomeAgentAddressDiscoveryRequestMessage(ICMPv6Data):
    pass

class ICMPv6HomeAgentAddressDiscoveryReplyMessage(ICMPv6Data):
    pass

class ICMPv6MobilePrefixSolicitation(ICMPv6Data):
    pass

class ICMPv6MobilePrefixAdvertisement(ICMPv6Data):
    pass

class ICMPv6NeighborSolicitation(ICMPv6Data):
    # pass
    __slots__ = ['_targetaddr']
    _PACKFMT = "!xxxx16s"
    '''
        possible options:
          * source_link_layer_address: link layer address of sending host
    '''

    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        super().__init__(**kwargs)

    def to_bytes(self):
        # return b''.join(super().to_bytes())
        return b''.join( (struct.pack(ICMPv6NeighborSolicitation._PACKFMT, self._targetaddr.packed), super().to_bytes()) )

    def from_bytes(self):
        pass

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        print("setting target address: {}".format(IPv6Address(value)))
        self._targetaddr = IPv6Address(value)

class ICMPv6NeighborAdvertisement(ICMPv6Data):
    __slots__ = ['_R_S_O','_targetaddr']
    _PACKFMT = "!cxxx16s"
    '''
        possiblie options:
          * source_link_layer_address: link layer address of sending host
    '''
    pass

def construct_icmpv6_class_map():
    clsmap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
        except:
            cls = None
        clsmap[xtype] = cls
    def inner(icmptype):
        icmptype = ICMPv6Type(icmptype)
        return clsmap.get(icmptype, None)
    return inner

def construct_icmpv6_type_map():
    typemap = {}
    for xtype in ICMPv6Type:
        clsname = "ICMPv6{}".format(xtype.name)
        try:
            cls = eval(clsname)
            typemap[cls] = xtype
        except:
            pass
    def inner(icmpcls):
        return typemap.get(icmpcls, None)
    return inner    

ICMPv6ClassFromType = construct_icmpv6_class_map()
ICMPv6TypeFromClass = construct_icmpv6_type_map()
