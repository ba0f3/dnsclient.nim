import streams, ../types, ../utils

type ARecord* = ref object of ResourceRecord
    address*: int32

proc `$`*(r: ARecord): string = ipv4ToString(r.address)

proc toARecord*(rr: ResourceRecord): ARecord =
    assert(rr.kind == A)
    result = cast[ARecord](rr)
    result.address =result.rdata.readInt32()
    result.rdata.close()

