type TXTRecord* = ref object of ResourceRecord
    length*: int8
    data*: string

method toString*(r: TXTRecord): string = r.data

method parse*(r: TXTRecord, data: StringStream) =
    r.length = data.readInt8()
    r.data = data.readStr(r.length)