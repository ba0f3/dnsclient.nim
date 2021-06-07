type PTRRecord* = ref object of ResourceRecord
  ptrdname*: string

method toString*(r: PTRRecord): string = r.ptrdname

method parse*(r: PTRRecord, data: StringStream) =
  r.ptrdname = data.getName()
