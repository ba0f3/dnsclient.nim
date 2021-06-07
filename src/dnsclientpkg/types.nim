import streams
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
      CS = 2
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
      MB = 7
      MG = 8
      MR = 9
      WKS = 11
      PTR = 12
      HINFO = 13
      MINFO = 14
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

    ResourceRecord* = ref object of RootObj
      name*: string
      class*: QClass
      ttl*: uint32
      rdlength*: uint16
      kind*: QKind
      #rdata*: StringStream

    Response* = object
      header*: Header
      question*: Question
      answers*: seq[ResourceRecord]
      authorityRRs*: seq[ResourceRecord]



method parse*(r: ResourceRecord, data: StringStream) {.base.} =
  raise newException(LibraryError, "parser for " & $r.kind & " is not implemented yet")

method toString*(r: ResourceRecord): string {.base.} =
  raise newException(LibraryError, "to override!")