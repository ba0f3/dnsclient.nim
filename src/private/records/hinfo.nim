type HINFORecord* = ref object of ResourceRecord
  cpu*: string
  os*: string

method toString*(r: HINFORecord): string = r.cpu & " " & r.os

method parse*(r: HINFORecord, data: StringStream) =
  r.cpu = data.readStr(data.readInt8())
  r.os = data.readStr(data.readInt8())
