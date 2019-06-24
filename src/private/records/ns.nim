import streams, ../types, ../utils

type NSRecord* = ref object of ResourceRecord
    nsdname*: string

proc `$`*(r: NSRecord): string = r.nsdname

proc toNSRecord*(rr: ResourceRecord): NSRecord =
    assert(rr.kind == NS)
    result = cast[NSRecord](rr)
    result.nsdname = result.rdata.getName()
    result.rdata.close()
