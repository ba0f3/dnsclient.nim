type MXRecord* = ref object of ResourceRecord
  preference*: uint16
  mx*: string

method toString*(r: MXRecord): string = $r.preference & " " & r.mx

method parse*(r: MXRecord, data: StringStream) =
  r.preference = data.readShort()
  r.mx = data.getName()
