type AAAARecord* = ref object of ResourceRecord
  address_v6*: array[16, uint8]

method toString*(r: AAAARecord): string = ipv6ToString(r.address_v6)

method parse*(r: AAAARecord, data: StringStream) =
  for i in 0..<16:
    r.address_v6[i] = data.readUInt8()
