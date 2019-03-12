import strutils, streams, endians, utils

type
  QQuery* = enum
    QR_QUERY = 0
    QR_RESPONSE = 1

  QAuthority* = enum
    AA_NONAUTHORITY = 0
    AA_AUTHORITY = 1

  QOpCode* = enum
    OPCODE_QUERY = 0
    OPCODE_IQUERY = 1
    OPCODE_STATUS = 2

  QClass* = enum
    IN = 1
    CH = 3
    HS = 4
    NONE = 254
    ALL = 255

  QKind* = enum
    UNUSED = 0
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    SIG = 24
    KEY = 25
    AAAA = 28
    LOC = 29
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    DNAME = 39
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    HIP = 55
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    TKEY = 249
    TSIG = 250
    ANY = 255
    URI = 256
    CAA = 257
#    TA = 32768
#    DLV = 32769

  Header* = object
    id*: uint16
    qr* {.bitsize:1.}: QQuery
    opcode* {.bitsize:4.}: QOpCode
    aa* {.bitsize:1.}: QAuthority
    tc* {.bitsize:1.}: uint16
    rd* {.bitsize:1.}: uint16
    ra* {.bitsize:1.}: uint16
    z* {.bitsize:3.}: uint16
    rcode* {.bitsize:4}: uint16
    qdcount*: uint16
    ancount*: uint16
    nscount*: uint16
    arcount*: uint16

  Question* = object
    name*: string
    kind*: QKind
    class*: QClass

  ResourceRecord* = object
    name: string
    class: QClass
    ttl: uint32
    rdlength: uint16
    case kind: QKind
    of TXT:
      txtlength: int8
      txtdata: string
    of MX:
      preference: uint16
      mx: string
    of HINFO:
      cpu: string
      os: string
    else:
      rdata: string


proc dump*(h: Header) =
  let
    opcode = if h.qr == QR_QUERY: "QUERY" else: "RESPONSE"
    rcode = if h.rcode == 0: "NOERROR" else: $(h.rcode)

  echo ";; ->>HEADER<<- opcode: $#, status: $#, id: $#" % [opcode, rcode, $h.id]
  echo ";; QUERY: $#, ANSWER: $#, AUTHORITY: $#, ADDITIONAL: $#" % [$h.qdcount, $h.ancount, $h.nscount, $h.arcount]

proc dump*(q: Question) =
  echo ";; QUESTION SECTION:"
  echo ";$#.\t\t\t$#\t$#" % [q.name, $q.class, $q.kind]


proc dump*(rr: seq[ResourceRecord], section = "ANSWER") =
  if len(rr) <= 0:
    return
  echo ";; $# SECTION:" % section
  for r in rr:
    var data = ""
    case r.kind
    of TXT:
      data = r.txtdata
    of MX:
      data = "$# $#" % [$r.preference, r.mx]
    of HINFO:
      data = "\"$#\" \"$#\"" % [r.cpu, r.os]
    else:
      data = r.rdata
    echo "$#.\t\t\t$#\t$#\t$#\t$#" % [r.name, $r.ttl, $r.class, $r.kind, data]

proc initHeader*(): Header =
  result.id = 2018
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
  var flags = data.readInt16().uint16
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
  result.name = data.getName()
  echo "name ", result.name
  result.kind = QKind(data.readShort())
  result.class = QClass(data.readShort())
  result.ttl = data.readInt()
  result.rdlength = data.readShort()
  #result.rdata = data.getName()
  case result.kind
  of TXT:
    result.txtlength = data.readInt8()
    result.txtdata = data.readStr(result.txtlength)
  of AAAA:
    result.rdata = data.readStr(result.rdlength.int)
  of MX:
    result.preference = data.readShort()
    result.mx = data.getName()
  of HINFO:
    result.cpu = data.readStr(data.readInt8())
    result.os = data.readStr(data.readInt8())
  else:
    result.rdata = data.getName()


proc parseResponse*(data: StringStream) =
  var
    header = parseHeader(data)
    question = parseQuestion(data)
    answers: seq[ResourceRecord] = @[]
    authorityRRs: seq[ResourceRecord] = @[]

  echo header
  dump(header)
  dump(question)
  echo "-------------------"
  for _ in 0..<header.ancount.int:
     var answer = parseRR(data)
     answers.add(answer)

  for _ in 0..<header.nscount.int:
    var answer = parseRR(data)
    authorityRRs.add(answer)


  dump(answers)
  dump(authorityRRs, "AUTHORITY")
