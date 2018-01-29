import strutils

type
  Query* = enum
    QR_QUERY = 0
    QR_RESPONSE = 1

  Authority* = enum
    AA_NONAUTHORITY = 0
    AA_AUTHORITY = 1

  OpCode* = enum
    OPCODE_QUERY = 0
    OPCODE_IQUERY = 1
    OPCODE_STATUS = 2

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
    qr* {.bitsize:1.}: Query
    opcode* {.bitsize:4.}: OpCode
    aa* {.bitsize:1.}: Authority
    tc* {.bitsize:1.}: uint16
    rd* {.bitsize:1.}: uint16
    ra* {.bitsize:1.}: uint16
    z* {.bitsize:4.}: uint16
    rcode*: uint16
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

  Question* = object
    qname: string
    qkind: QKind
    qclass: uint16

proc initHeader*(id=2018, qr=QR_QUERY, opcode=OPCODE_QUERY, tc=0, rd=1, qdcount=1): Header =
  result.id = id.uint16
  result.qr = qr
  result.opcode = opcode
  result.tc = tc.uint16
  result.rd = rd.uint16
  result.qdcount = qdcount.uint16

proc initQuestion(name: string, kind: QKind = A): Question =
  result.qname = name
  result.qkind = kind
  result.qclass= 1

proc dump*(h: Header) =
  let
    opcode = if h.qr == QR_QUERY: "QUERY" else: "RESPONSE"
    rcode = if h.rcode == 0: "NOERROR" else: $(h.rcode)

  echo ";; ->>HEADER<<- opcode: $#, status: $#, id: $#" % [opcode, rcode, $h.id]
  echo ";; QUERY: $#, ANSWER: $#, AUTHORITY: $#, ADDITIONAL: $#" % [$h.qdcount, $h.ancount, $h.nscount, $h.arcount]

proc dump*(q: Question) =
  echo ";; QUESTION SECTION:"
  echo ";google.com.			IN	SOA" % [q.qname, $q.qclass, $q.qkind]
