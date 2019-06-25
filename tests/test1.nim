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

test "query TXT":
  let resp = client.sendQuery("txt.example.huy.im", TXT)
  assert resp.answers[0].kind == TXT
  let rr = TXTRecord(resp.answers[0])
  assert rr.data == "dnsclient.nim"

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