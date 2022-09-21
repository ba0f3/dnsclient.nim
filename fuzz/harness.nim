import streams, dnsclient, dnsclientpkg/protocol

proc fuzz_target(input: string) {.exportc.} =

  try:
    var resp = parseResponse(input)
    echo "OK"
  except ValueError:
    echo "FAIL: ", getCurrentExceptionMsg()


when isMainModule:
  let input = readAll(stdin);
  fuzz_target(input)


