import streams, ../types, ../utils

type NSRecord* = ref object of ResourceRecord
    nsdname*: string

proc `$`*(r: NSRecord): string = r.nsdname

proc toNSRecord*(rr: ResourceRecord): NSRecord =
    assert(rr.kind == NS)
    new(result)
    result.name = rr.name
    result.class = rr.class
    result.ttl = rr.ttl
    result.rdlength = rr.rdlength
    result.kind = rr.kind
    result.rdata = rr.rdata
    result.nsdname = result.rdata.getName()
    result.rdata.close()
