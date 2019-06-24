import streams, ../types, ../utils

type HINFORecord* = ref object of ResourceRecord
    cpu*: string
    os*: string

proc `$`*(r: HINFORecord): string = r.cpu & " " & r.os

proc toHINFORecord*(rr: ResourceRecord): HINFORecord =
    assert(rr.kind == HINFO)
    result = cast[HINFORecord](rr)
    result.cpu = result.rdata.readStr(result.rdata.readInt8())
    result.os = result.rdata.readStr(result.rdata.readInt8())
    result.rdata.close()
