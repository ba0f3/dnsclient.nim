# dnsclient
# Copyright Huy Doan
# Simple DNS client

import strutils, streams, net, nativesockets, endians
import private/[protocol, records, types]

export records, types

type
  DNSClient = ref object of RootObj
    server: string
    port: Port
    socket: Socket

proc newDNSClient*(server: string, port: Port): DNSClient =
  new(result)
  result.socket = newSocket(sockType=SOCK_DGRAM,protocol=IPPROTO_UDP)
  result.server = server
  result.port = port

proc newDNSClient*(server = "8.8.8.8", port = 53): DNSClient =
  result = newDNSClient(server, Port(port))

proc sendQuery*(c: DNSClient, query: string, kind: QKind = A) =
  var
    header = initHeader()
    question = initQuestion(query, kind)

  var buf = header.toStream()
  question.toStream(buf)
  var bufLen = buf.getPosition()
  buf.setPosition(0)

  var data = newStringOfCap(bufLen)
  discard buf.readData(addr data, bufLen)

  c.socket.sendTo(c.server, c.port, addr data, bufLen)
  #if ret != bufLen:
  #  raise newException(IOError, "dns question sent fail")

  bufLen = 4096
  var resp = newStringOfCap(bufLen)
  discard c.socket.recvFrom(resp, bufLen, c.server, c.port)

  buf.setPosition(0)
  buf.write(resp)
  buf.setPosition(0)
  parseResponse(buf)

when isMainModule:
  let client = newDNSClient()
  client.sendQuery("huy.im", A)

