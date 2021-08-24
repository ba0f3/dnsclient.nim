type TXTRecord* = ref object of ResourceRecord
    length*: uint8
    data*: string

method toString*(r: TXTRecord): string = r.data

method parse*(r: TXTRecord, data: StringStream) =
    r.length = data.readUint8()
    r.data = data.readStr(r.length.int)
