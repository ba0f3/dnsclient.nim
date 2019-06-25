type MBRecord* = ref object of ResourceRecord
    madname*: string

method toString*(r: MBRecord): string = r.madname

method parse*(r: MBRecord, data: StringStream) =
    r.madname = data.getName()