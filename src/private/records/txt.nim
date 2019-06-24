import streams, ../types

type TXTRecord* = ref object of ResourceRecord
    length*: int8
    data*: string

proc `$`*(r: TXTRecord): string = r.data

proc toTXTRecord*(rr: ResourceRecord): TXTRecord =
    assert(rr.kind == TXT)
    result = cast[TXTRecord](rr)
    result.length = result.rdata.readInt8()
    result.data = result.rdata.readStr(result.length)
    result.rdata.close()

