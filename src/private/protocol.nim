import strutils, streams, endians, utils, random
import types, records

randomize()

proc dumpHeader*(h: Header) =
  let
    opcode = if h.qr == QR_QUERY: "QUERY" else: "RESPONSE"
    rcode = if h.rcode == 0: "NOERROR" else: $(h.rcode)

  echo ";; ->>HEADER<<- opcode: $#, status: $#, id: $#" % [opcode, rcode, $h.id]
  echo ";; QUERY: $#, ANSWER: $#, AUTHORITY: $#, ADDITIONAL: $#" % [$h.qdcount, $h.ancount, $h.nscount, $h.arcount]

proc dumpQuestion*(q: Question) =
  echo ";; QUESTION SECTION:"
  echo ";$#.\t\t\t$#\t$#" % [q.name, $q.class, $q.kind]


proc dumpRR*(rr: seq[ResourceRecord], section = "ANSWER") =
  if len(rr) <= 0:
    return
  echo ";; $# SECTION:" % section
  for r in rr:
    echo "$#.\t\t\t$#\t$#\t$#\t$#" % [r.name, $r.ttl, $r.class, $r.kind, r.toString()]

proc initHeader*(): Header =
  result.id = rand(high(uint16).int).uint16
  result.qr = QR_QUERY
  result.opcode = OPCODE_QUERY
  result.tc = 0
  result.rd = 1
  result.qdcount = 1


proc toStream*(h: var Header): StringStream =
  result = newStringStream()
  var flags: uint16

  result.writeShort(h.id)

  flags = 0
  flags = flags or h.qr.uint16
  flags = flags shl 1
  flags = flags or h.opcode.uint16
  flags = flags shl 4
  flags = flags or h.aa.uint16
  flags = flags shl 1
  flags = flags or h.tc
  flags = flags shl 1
  flags = flags or h.rd
  flags = flags shl 1
  flags = flags or h.ra
  flags = flags shl 7
  flags = flags or h.rcode

  result.writeShort(flags)
  result.writeShort(h.qdcount)
  result.writeShort(h.ancount)
  result.writeShort(h.nscount)
  result.writeShort(h.arcount)


proc initQuestion*(name: string, kind: QKind = A): Question =
  result.name = name
  result.kind = kind
  result.class= IN


proc toStream*(q: var Question, data: StringStream) =
  var labelLen: uint8
  for label in q.name.split('.'):
    labelLen = label.len.uint8
    if labelLen < 1.uint8:
      raise newException(ValueError, q.name & "is not a legal name (empty label)")
    if labelLen >= 64.uint8:
      raise newException(ValueError, q.name & "is not a legal name (label too long)")

    data.write(labelLen)
    data.write(label)
  data.write('\0')

  data.writeShort(q.kind.uint16)
  data.writeShort(q.class.uint16)


proc parseHeader(data: StringStream): Header =
  result.id = data.readShort()
  var flags = data.readUint16()
  result.rcode = flags and 15
  flags = flags shr 7
  result.ra = flags and 1
  flags = flags shr 1
  result.rd = flags and 1
  flags = flags shr 1
  result.tc = flags and 1
  flags = flags shr 1
  result.aa = QAuthority(flags and 1)
  flags = flags shr 1
  result.opcode = QOpCode(flags and 15)
  flags = flags shr 4
  result.qr = QQuery(flags)
  result.qdcount = data.readShort()
  result.ancount = data.readShort()
  result.nscount = data.readShort()
  result.arcount = data.readShort()

proc parseQuestion(data: StringStream): Question =
  result.name = data.getName()
  result.kind = QKind(data.readShort())
  result.class = QClass(data.readShort())

proc parseRR(data: StringStream): ResourceRecord =
  # name offset
  new(result)
  let
    name = data.getName()
    kind = QKind(data.readShort())
  case kind
  of A:
    result = ARecord(name: name, kind: kind)
  of CNAME:
    result = CNAMERecord(name: name, kind: kind)
  of HINFO:
    result = HINFORecord(name: name, kind: kind)
  of MB:
    result = MBRecord(name: name, kind: kind)
  of MINFO:
    result = MINFORecord(name: name, kind: kind)
  of MR:
    result = MRRecord(name: name, kind: kind)
  of MX:
    result = MXRecord(name: name, kind: kind)
  of NS:
    result = NSRecord(name: name, kind: kind)
  of PTR:
    result = PTRRecord(name: name, kind: kind)
  of SOA:
    result = SOARecord(name: name, kind: kind)
  of TXT:
    result = TXTRecord(name: name, kind: kind)
  of SRV:
    result = SRVRecord(name: name, kind: kind)
  else:
    raise newException(ValueError, "RR for " & $kind & " is not implemented yet")

  result.class = QClass(data.readShort())
  result.ttl = data.readTTL().uint32
  result.rdlength = data.readShort()
  result.parse(data)

proc parseResponse*(data: StringStream): Response =
  result.header = parseHeader(data)
  result.question = parseQuestion(data)

  for _ in 0..<result.header.ancount.int:
     var answer = parseRR(data)
     result.answers.add(answer)

  for _ in 0..<result.header.nscount.int:
    var answer = parseRR(data)
    result.authorityRRs.add(answer)
  assert data.atEnd()
  data.close()
