type TXTRecord* = ref object of ResourceRecord
    strings*: seq[string]

method toString*(r: TXTRecord): string = r.strings.join()

method parse*(r: TXTRecord, data: StringStream) =
    var bytesLeft = r.rdlength.int
    while bytesLeft > 0:
        let length = data.readUint8()
        r.strings.add(data.readStr(length.int))
        bytesLeft -= length.int + 1
