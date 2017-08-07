import struct
from ipaddress import IPv6Address
from abc import ABCMeta

from .icmp import ICMP, ICMPData, ICMPEchoRequest, ICMPEchoReply
from .common import ICMPv6Type, ICMPv6TypeCodeMap, ICMPv6OptionNumber
from .common import checksum as csum
from ..address import EthAddr
from ..exceptions import *
from sys import byteorder

'''
References:
    http://tools.ietf.org/html/rfc4443
    Stevens, Fall, TCP/IP Illustrated, Vol 1., 2nd Ed.
    https://notes.shichao.io/tcpv1/ch8/
'''


class ICMPv6(ICMP):
    def __init__(self, **kwargs):
        # Another hacky way to make this thing work.. super should be last..
        if 'icmptype' in kwargs:
            self.icmp6type = kwargs['icmptype']
            del kwargs['icmptype']
        super().__init__(**kwargs)
        if hasattr(self, "icmp6type"):
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

class ICMPv6Option(object, metaclass=ABCMeta):
    _PACKFMT = 'B'
    __slots__ = ['_optnum']
    def __init__(self, optnum):
        self._optnum = ICMPv6OptionNumber(optnum)

    @property
    def optnum(self):
        return self._optnum

    def length(self):
        return struct.calcsize(ICMPv6Option._PACKFMT)

    def to_bytes(self):
        return struct.pack(ICMPv6Option._PACKFMT, self._optnum.value)

    def from_bytes(self, raw):
        return self.length()

    def __eq__(self, other):
        return self._optnum == other._optnum

    def __str__(self):
        return "{}".format(self.__class__.__name__)

class ICMPv6OptionLinkLayerAddress(ICMPv6Option):
    _PACKFMT = '6s'

    def __init__(self, address=None):
        super().__init__(self._ICMPv6OptionType)
        self._linklayeraddress = EthAddr(address)

    def to_bytes(self):
        v = self._linklayeraddress.packed
        l = int.to_bytes(int((len(v) + 2)/8), length=1, byteorder=byteorder, signed=False)
        t = int.to_bytes(self._ICMPv6OptionType, length=1, byteorder=byteorder, signed=False)
        return t+l+v

    def from_bytes(self, raw):
        self._linklayeraddress = EthAddr(raw)
        return len(raw) # length of data unpacked

    def __str__(self):
        return "{} {}".format(super().__str__(), self._linklayeraddress)

class ICMPv6OptionSourceLinkLayerAddress(ICMPv6OptionLinkLayerAddress):
    _ICMPv6OptionType = ICMPv6OptionNumber.SourceLinkLayerAddress

class ICMPv6OptionTargetLinkLayerAddress(ICMPv6OptionLinkLayerAddress):
    _ICMPv6OptionType = ICMPv6OptionNumber.TargetLinkLayerAddress


class ICMPv6OptionPrefixInformation(ICMPv6Option):
    pass

class ICMPv6OptionRedirectedHeader(ICMPv6Option):
    pass

class ICMPv6OptionMTU(ICMPv6Option):
    pass

ICMPv6OptionClasses = {
    ICMPv6OptionNumber.SourceLinkLayerAddress: ICMPv6OptionSourceLinkLayerAddress,
    ICMPv6OptionNumber.TargetLinkLayerAddress: ICMPv6OptionTargetLinkLayerAddress,
    ICMPv6OptionNumber.PrefixInformation: ICMPv6OptionPrefixInformation,
    ICMPv6OptionNumber.RedirectedHeader: ICMPv6OptionRedirectedHeader,
    ICMPv6OptionNumber.MTU: ICMPv6OptionMTU
}

class ICMPv6OptionList(object):
    def __init__(self):
        self._options = []

    @staticmethod
    def from_bytes(rawbytes):
        '''
        Takes a byte string as a parameter and returns a list of
        ICMPv6Option objects.
        '''
        icmpv6popts = ICMPv6OptionList()

        i = 0
        while i < len(rawbytes):
            opttype = rawbytes[i]
            optnum = ICMPv6OptionNumber(opttype)
            obj = ICMPv6OptionClasses[optnum]()
            eaten = obj.from_bytes(rawbytes[i:])
            i += eaten
            icmpv6popts.append(obj)
        return icmpv6popts

    def to_bytes(self):
        '''
        Takes a list of ICMPv6Option objects and returns a packed byte string
        of options, appropriately padded if necessary.
        '''
        raw = b''
        if not self._options:
            return raw
        for icmpv6popt in self._options:
            raw += icmpv6popt.to_bytes()
        # Padding doesn't seem necessary?
        #   RFC states it should be padded to 'natural 64bit boundaries'
        #   However, wireshark interprets \x00 as a malformed option field
        #   So for now, ignore padding
        # padbytes = 4 - (len(raw) % 4)
        # raw += b'\x00'*padbytes
        return raw
    
    def append(self, opt):
        if isinstance(opt, ICMPv6Option):
            self._options.append(opt)
        else:
            raise Exception( "Option to be added must be an ICMPv6Option object ( is {} )".format(type(opt)) )

    def __len__(self):
        return len(self._options)

    def __getitem__(self, i):
        if i < 0:
            i = len(self._options) + i
        if 0 <= i < len(self._options):
            return self._options[i]
        raise IndexError("Invalid IP option index")

    def __setitem__(self, i, val):
        if i < 0:
            i = len(self._options) + i
        if not issubclass(val.__class__, ICMPv6Option):
            raise ValueError("Assigned value must be of type ICMPv6Option, but {} is not.".format(val.__class__.__name__))
        if 0 <= i < len(self._options):
            self._options[i] = val
        else:
            raise IndexError("Invalid IP option index")

    def __delitem__(self, i):
        if i < 0:
            i = len(self._options) + i
        if 0 <= i < len(self._options):
            del self._options[i]
        else:
            raise IndexError("Invalid IP option index")

    def raw_length(self):
        return len(self.to_bytes())

    def size(self):
        return len(self._options)

    def __eq__(self, other):
        if not isinstance(other, ICMPv6OptionList):
            return False
        if len(self._options) != len(other._options):
            return False
        return self._options == other._options

    def __str__(self):
        return "{} ({})".format(self.__class__.__name__,
            ", ".join([str(opt) for opt in self._options]))


class ICMPv6Data(ICMPData):
    '''Hack to make the inheritance chain happy and lead into v6 specific differences'''
    def __init__(self, **kwargs):
        self._options = ICMPv6OptionList()
        super().__init__(**kwargs)

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
    __slots__ = ['_targetaddr']
    _PACKFMT = "!xxxx16s"
    _MINLEN = struct.calcsize(_PACKFMT)
    '''
        possible options:
          * source_link_layer_address: link layer address of sending host
    '''

    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        super().__init__(**kwargs)

    def to_bytes(self):
        return b''.join( (struct.pack(ICMPv6NeighborSolicitation._PACKFMT, self._targetaddr.packed), self._options.to_bytes(), super().to_bytes()) )

    def from_bytes(self, raw):
        if len(raw) < self._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack ICMPv6NeighborSolicitation object")
        optionbytes = raw[self._MINLEN:]
        fields = struct.unpack(ICMPv6NeighborSolicitation._PACKFMT, raw)
        self._targetaddr = IPv6Address(fields[0])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        print("setting target address: {}".format(IPv6Address(value)))
        self._targetaddr = IPv6Address(value)
    
    @property
    def options(self):
        return self._options
    
    def __str__(self):
        s = "Target address: {}".format(self._targetaddr)
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s

class ICMPv6NeighborAdvertisement(ICMPv6Data):
    __slots__ = ['_R_S_O','_targetaddr']
    _PACKFMT = "!cxxx16s"
    _MINLEN = struct.calcsize(_PACKFMT)
    '''
        possible options:
          * source_link_layer_address: link layer address of sending host
    '''
    def __init__(self, **kwargs):
        self._targetaddr = IPv6Address("::0")
        self._routerflag = 0
        self._solicitedflag = 0
        self._overrideflag = 0
        super().__init__(**kwargs)
        
    def to_bytes(self):
        return b''.join( (struct.pack(ICMPv6NeighborAdvertisement._PACKFMT, self.get_rso_byte(), self._targetaddr.packed), self._options.to_bytes(), super().to_bytes()) )

    def from_bytes(self, raw):
        if len(raw) < self._MINLEN:
            raise NotEnoughDataError("Not enough bytes to unpack ICMPv6NeighborAdvertisement object")
        optionbytes = raw[ICMPv6NeighborAdvertisement._MINLEN:]
        fields = struct.unpack(ICMPv6NeighborSolicitation._PACKFMT, raw[:ICMPv6NeighborAdvertisement._MINLEN])
        rso = int.from_bytes(fields[0], byteorder=byteorder, signed=False)
        self._routerflag = (rso & 0x80) >> 7
        self._solicitedflag = (rso & 0x40) >> 6
        self._overrideflag = (rso & 0x20) >> 5
        self._targetaddr = IPv6Address(fields[0])
        self._options = ICMPv6OptionList.from_bytes(optionbytes)

    def get_rso_byte(self):
        rso = self._routerflag << 7 | self._solicitedflag << 6 | self._overrideflag << 5
        return int.to_bytes(rso, length=1, byteorder=byteorder, signed=False)

    @property
    def targetaddr(self):
        return self._targetaddr

    @targetaddr.setter
    def targetaddr(self, value):
        self._targetaddr = IPv6Address(value)
    
    @property
    def routerflag(self):
        return bool(self._routerflag)
    
    @property
    def solicitedflag(self):
        return bool(self._solicitedflag)
    
    @property
    def overrideflag(self):
        return bool(self._overrideflag)
      
    @routerflag.setter
    def routerflag(self, value):
        assert value == True or value == False
        self._routerflag = int(value)
    
    @solicitedflag.setter
    def solicitedflag(self, value):
        assert value == True or value == False
        self._solicitedflag = int(value)
    
    @overrideflag.setter
    def overrideflag(self, value):
        assert value == True or value == False
        self._overrideflag = int(value)
    
    @property
    def options(self):
        return self._options
    
    def __str__(self):
        s = "Target address: {} flags: {}".format(self._targetaddr, hex(int.from_bytes(self.get_rso_byte(), byteorder=byteorder, signed=False)))
        if len(self._options) > 0:
            s = "{} | {}".format(s, self._options)
        return s
    

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
