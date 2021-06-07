type NSRecord* = ref object of ResourceRecord
  nsdname*: string

method toString*(r: NSRecord): string = r.nsdname

method parse*(r: NSRecord, data: StringStream) =
  r.nsdname = data.getName()
