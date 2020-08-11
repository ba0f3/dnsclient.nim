# dnsclient
# Copyright Huy Doan
# Simple DNS client

import strutils, streams, net, nativesockets, endians
import private/[protocol, records, types]

export records, types, TimeoutError

type
  DNSClient = ref object of RootObj
    server: string
    port: Port
    socket: Socket

proc newDNSClient*(server: string, port: Port): DNSClient =
  ## Create new DNS client
  new(result)
  result.socket = newSocket(sockType=SOCK_DGRAM,protocol=IPPROTO_UDP)
  result.server = server
  result.port = port

proc newDNSClient*(server = "8.8.8.8", port = 53): DNSClient =
  ## Create new DNS client with default dns server `8.8.8.8`
  result = newDNSClient(server, Port(port))

proc sendQuery*(c: DNSClient, query: string, kind: QKind = A, timeout = 500): Response =
  ## send dns query to server
  var
    header = initHeader()
    question = initQuestion(query, kind)

  var buf = header.toStream()
  question.toStream(buf)
  var bufLen = buf.getPosition()
  buf.setPosition(0)

  var data = newStringOfCap(bufLen)
  data.setLen 1
    # ugly hack, nim should provide a way to get address of 1st element of a string
    # with non-zero capacity (ie underlying c object not nil) and with 0 elements
  data[0] = 'x'
  let n = buf.readData(data[0].addr, bufLen)
  doAssert n == bufLen
  c.socket.sendTo(c.server, c.port, data[0].addr, bufLen)

  bufLen = 1024
  var
    resp = newStringOfCap(bufLen)
    readFds = @[c.socket.getFd]
  if selectRead(readFds, timeout) > 0:
    discard c.socket.recvFrom(resp, bufLen, c.server, c.port)
  else:
    raise newException(TimeoutError, "Call to 'sendQuery' timed out.")

  buf.setPosition(0)
  buf.write(resp)
  buf.setPosition(0)
  result = parseResponse(buf)

proc close*(c: DNSClient) = c.socket.close()

when isMainModule:
  import os
  if paramCount() != 2:
    quit("Usage: " & getAppFilename() & " q-type host")
  let client = newDNSClient()

  var
    qtype = paramStr(1)
    kind: QKind
  for k in QKind.low..QKind.high:
    if qtype == $k:
      kind = k
      break
  if kind == UNUSED:
    quit("unsupported q-type")

  let resp = client.sendQuery(paramStr(2), kind)
  dumpHeader(resp.header)
  dumpQuestion(resp.question)
  dumpRR(resp.answers)
  dumpRR(resp.authorityRRs, "AUTHORITY")
