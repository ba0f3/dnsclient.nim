type MXRecord* = ref object of ResourceRecord
  preference*: uint16
  exchange*: string

method toString*(r: MXRecord): string = $r.preference & " " & r.exchange

method parse*(r: MXRecord, data: StringStream) =
  r.preference = data.readShort()
  r.exchange = data.getName()
