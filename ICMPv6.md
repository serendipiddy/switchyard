Documentation for ICMPv6
========================

Switchyard has been modified to include the following ICMPv6 packet headers, which are part of the Network Discovery Protocol, [RFC4861](http://tools.ietf.org/html/rfc4861).

* ICMPv6NeighborSolicitation
* ICMPv6NeighborAdvertisement
* ICMPv6RedirectMessage

To create an ICMPv6 packet you need to create and ICMPv6 packet while defining its icmptype.

The properties can be set by using the dot operator, eg:

```
icmpv6 = ICMPv6()
icmp.icmptype = ICMPv6Type.RedirectMessage

## OR Directly when initialising the ICMPv6 header
# icmpv6 = ICMPv6(icmptype=ICMPv6Type.RedirectMessage)

r = ICMPv6RedirectMessage()  
# or r = icmpv6.icmpdata if already assigned to ICMPv6 object
r.targetaddr = IPv6Address( "::0" )
r.options.append( ICMPv6OptionRedirectedHeader( redirected_packet=p ))
r.options.append( ICMPv6OptionTargetLinkLayerAddress( address=IPv6Address( "::0" ) )

icmpv6.icmpdata = r
```

There are several ICMPv6 options which can be attached to these:

* ICMPv6OptionSourceLinkLayerAddress
* ICMPv6OptionTargetLinkLayerAddress
* ICMPv6OptionRedirectedHeader


ICMPv6NeighborSolicitation
--------------------------

### Properties
* targetaddr
* options


ICMPv6NeighborAdvertisement
---------------------------

### Properties
* targetaddr
* routerflag
* solicitedflag
* overrideflag
* options

ICMPv6RedirectMessage
---------------------

### Properties
* targetaddr
* destinationaddr
* options

ICMPv6Option
------------

* ICMPv6OptionSourceLinkLayerAddress( address : IPv6Address )

* ICMPv6OptionTargetLinkLayerAddress( address : IPv6Address )

* ICMPv6OptionRedirectedHeader( redirected_packet : Packet )