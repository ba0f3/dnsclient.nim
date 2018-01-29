import endians


proc pack*(inp: int16): uint16 {.inline.} =
  var inp = inp.uint16
  bigEndian16(addr result, addr inp)


proc pack*(inp: uint16): uint16 {.inline.} =
  var inp = inp
  bigEndian16(addr result, addr inp)
