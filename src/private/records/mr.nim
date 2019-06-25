type MRRecord* = ref object of ResourceRecord
    newname*: string

method toString*(r: MRRecord): string = r.newname

method parse*(r: MRRecord, data: StringStream) =
    r.newname = data.getName()