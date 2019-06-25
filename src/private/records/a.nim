type ARecord* = ref object of ResourceRecord
  address*: int32

method toString*(r: ARecord): string = ipv4ToString(r.address)

method parse*(r: ARecord, data: StringStream) =
  r.address = data.readInt32()
