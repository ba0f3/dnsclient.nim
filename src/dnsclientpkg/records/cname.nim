type CNAMERecord* = ref object of ResourceRecord
  cname*: string

method toString*(r: CNAMERecord): string = r.cname

method parse*(r: CNAMERecord, data: StringStream) =
  r.cname = data.getName()
