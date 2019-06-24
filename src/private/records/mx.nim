import streams, ../types, ../utils

type MXRecord* = ref object of ResourceRecord
    preference*: uint16
    mx*: string

proc `$`*(r: MXRecord): string = $r.preference & " " & r.mx

proc toMXRecord*(rr: ResourceRecord): MXRecord =
    assert(rr.kind == MX)
    result = cast[MXRecord](rr)
    result.preference = result.rdata.readShort()
    result.mx = result.rdata.getName()
    result.rdata.close()
