Documentation for ICMPv6
========================

Switchyard has been modified to include the following ICMPv6 packet headers, which are part of the Network Discovery Protocol, [RFC4443](http://tools.ietf.org/html/rfc4443).

* ICMPv6NeighborSolicitation
* ICMPv6NeighborAdvertisement
* ICMPv6RedirectMessage

The properties can be set by using the dot operator, eg:

```
r = ICMPv6RedirectMessage()
r.targetaddr = IPv6Address( "::0" )
r.option.append( ICMPv6OptionRedirectedHeader( p ))
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