type SOARecord* = ref object of ResourceRecord
  mname*: string
  rname*: string
  serial*: uint32
  refresh*: int32
  retry*: int32
  expire*: int32
  minimum*: uint32

method toString*(r: SOARecord): string = "$# $# $# $# $# $# $#" % [r.mname, r.rname, $r.serial, $r.refresh, $r.retry, $r.expire, $r.minimum]

method parse*(r: SOARecord, data: StringStream) =
  r.mname = data.getName()
  r.rname = data.getName()
  r.serial = data.readTTL().uint32
  r.refresh = data.readTTL()
  r.retry = data.readTTL()
  r.expire = data.readTTL()
  r.minimum = data.readTTL().uint32
