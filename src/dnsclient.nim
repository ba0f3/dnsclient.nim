# dnsclient
# Copyright Huy Doan
# Simple DNS client


import strutils, net, nativesockets, random, private/protocol

randomize()

type
  DNSClient = ref object of RootObj
    server: string
    port: Port
    socket: Socket

proc newDNSClient*(server: string, port: Port): DNSClient =
  new(result)
  result.socket = newSocket()
  result.server = server
  result.port = port

proc newDNSClient*(server: string, port = 53): DNSClient =
  result = newDNSClient(server, Port(port))


proc `+`(p: pointer, offset: int): pointer =
  result = cast[pointer](cast[int](p) + offset)

proc sendQuery*(c: DNSClient, query: string, kind: QKind = A): string =
  let id = random(high(uint16).int).uint16
  var
    header = initHeader()
    buf = alloc0(256)
    bufLen = 12
  header.id = id
  header.qdcount = 1
  copyMem(buf, addr header, bufLen)

  for label in query.split('.'):
    var labelLen = label.len
    if labelLen < 1:
      raise newException(ValueError, query & "is not a legal name (empty label)")
    if labelLen > 63:
      raise newException(ValueError, query & "is not a legal name (label too long)")

    copyMem(buf+bufLen, addr labelLen, 1)
    inc(bufLen)
    copyMem(buf+bufLen, addr label, labelLen)
    inc(bufLen, labelLen)


  let ret = c.socket.sendTo(c.server, c.port, addr buf, bufLen)
  echo $ret



when isMainModule:
  let client = newDNSClient("8.8.8.8")
  var res = client.sendQuery("google.com")
