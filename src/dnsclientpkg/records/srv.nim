type SRVRecord* = ref object of ResourceRecord
    priority*: uint16
    weight*: uint16
    port*: uint16
    target*: string

method toString*(r: SRVRecord): string = $r.priority & " " & $r.weight &  " " & $r.port & " " & r.target

method parse*(r: SRVRecord, data: StringStream) =
    r.priority = data.readShort()
    r.weight = data.readShort()
    r.port = data.readShort()
    r.target = data.getName()