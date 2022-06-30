# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest, dnsclient

let client = newDNSClient()

test "query A":
  let resp = client.sendQuery("example.huy.im", A)
  assert resp.answers[0].kind == A
  let rr = ARecord(resp.answers[0])
  assert rr.toString() == "8.8.8.8"

test "query AAAA":
  let resp = client.sendQuery("google.fr", AAAA)
  assert resp.answers[0].kind == AAAA
  let rr = AAAARecord(resp.answers[0])
  #assert rr.toString() == "0000:0000:0000:0000:0000:0000:0000:0001" ??

test "query TXT":
  let resp = client.sendQuery("txt.example.huy.im", TXT)
  assert resp.answers[0].kind == TXT
  let rr = TXTRecord(resp.answers[0])
  assert rr.strings == @["dnsclient.nim"]

test "query MX":
  let resp = client.sendQuery("mx.example.huy.im", MX)
  assert resp.answers[0].kind == MX
  let rr = MXRecord(resp.answers[0])
  assert rr.preference == 5
  assert rr.exchange == "8.8.8.8"

test "query CNAME":
  let resp = client.sendQuery("cname.example.huy.im", CNAME)
  assert resp.answers[0].kind == CNAME
  let rr = CNAMERecord(resp.answers[0])
  assert rr.cname == "example.huy.im"

test "query SRV":
  let resp = client.sendQuery("_smtp._tcp.example.huy.im", SRV)
  assert resp.answers[0].kind == SRV
  let rr = SRVRecord(resp.answers[0])
  assert rr.priority == 10
  assert rr.weight == 15
  assert rr.port == 25
  assert rr.target == "smtp.yandex.ru"
