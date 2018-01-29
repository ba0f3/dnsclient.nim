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
    ANY = 255

  QKind* = enum
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
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
    URI = 256
    CAA = 257
    TA = 32768
    DLV = 32769

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

  ResponsePacket* = object
    name: string
    kind: uint16
    class: uint16
    ttl: uint32
    rdlenght: uint16
    rdata: cstring

  Query* = object
    qname*: string
    qkind*: QKind
    qclass*: QClass


proc dump*(h: Header) =
  let
    opcode = if h.qr == QR_QUERY: "QUERY" else: "RESPONSE"
    rcode = if h.rcode == 0: "NOERROR" else: $(h.rcode)

  echo ";; ->>HEADER<<- opcode: $#, status: $#, id: $#" % [opcode, rcode, $h.id]
  echo ";; QUERY: $#, ANSWER: $#, AUTHORITY: $#, ADDITIONAL: $#" % [$h.qdcount, $h.ancount, $h.nscount, $h.arcount]

proc dump*(q: Query) =
  echo ";; QUESTION SECTION:"
  echo ";$#.			$#	$#" % [q.qname, $q.qclass, $q.qkind]


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

  result.write(pack(h.id))

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

  result.write(pack(flags))
  result.write(pack(h.qdcount))
  result.write(pack(h.ancount))
  result.write(pack(h.nscount))
  result.write(pack(h.arcount))


proc initQuery*(name: string, kind: QKind = A): Query =
  result.qname = name
  result.qkind = kind
  result.qclass= IN


proc toStream*(q: var Query, data: StringStream) =
  var labelLen: uint8
  for label in q.qname.split('.'):
    labelLen = label.len.uint8
    if labelLen < 1.uint8:
      raise newException(ValueError, q.qname & "is not a legal name (empty label)")
    if labelLen >= 64.uint8:
      raise newException(ValueError, q.qname & "is not a legal name (label too long)")

    data.write(labelLen)
    data.write(label)
  data.write('\0')

  data.write(pack(q.qkind.uint16))
  data.write(pack(q.qclass.uint16))


proc parseHeader(data: StringStream): Header =
  result.id = pack(data.readInt16())
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
  result.qdcount = pack(data.readInt16())
  result.ancount = pack(data.readInt16())
  result.nscount = pack(data.readInt16())
  result.arcount = pack(data.readInt16())

proc parseQuery(data: StringStream): Query =
  var name = ""
  var labelLen = data.readInt8()
  while true:
    name.add(data.readStr(labelLen))
    labelLen = data.readInt8()
    if labelLen == 0:
      break
    name.add('.')
  result.qname = name
  result.qkind = pack(data.readInt16()).QKind
  result.qclass = pack(data.readInt16()).QClass


proc parseResponse*(data: StringStream) =
  var
    header = parseHeader(data)
    query = parseQuery(data)

  dump(header)
  dump(query)
