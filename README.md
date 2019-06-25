# dnsclient
Simple DNS Client and library in pure Nim

Installation
============
```
$ nimble install dnsclient
```

Usage
============

This is a hybird repo, contains a command line DNS client and library for DNS query.
For now, only some simple records are supported, but adding new records is very simple.

Feel free to make PR or raise an issue as your need!

### CLI
```
$ dnsclient TXT txt.example.huy.im
```

### Library
```nim
import dnsclient

let client = newDNSClient()
let resp = client.sendQuery("txt.example.huy.im", TXT)
assert resp.answers[0].kind == TXT
let rr = TXTRecord(resp.answers[0])
assert rr.data == "dnsclient.nim"
```