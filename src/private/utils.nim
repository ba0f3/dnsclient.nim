import endians, streams, strutils


#proc pack*(inp: int16): uint16 {.inline.} =
#  var inp = inp.uint16
#  bigEndian16(addr result, addr inp)


#proc pack*(inp: uint16): uint16 {.inline.} =
#  var inp = inp
#  bigEndian16(addr result, addr inp)

proc readInt*(s: StringStream): uint32 {.inline.} =
  var value = s.readInt32()
  bigEndian32(addr result, addr value)

proc readShort*(s: StringStream): uint16 {.inline.} =
  var value = s.readInt16()
  bigEndian16(addr result, addr value)

proc writeShort*[T: int16|uint16](s: StringStream, value: T) {.inline.} =
  var
    value = value
    input: T
  bigEndian16(addr input, addr value)
  s.write(input)

proc getName*(data: StringStream, offset = 0): string =
  var labels: seq[string] = @[]
  var lastPos: int
  if offset > 0:
    lastPos = data.getPosition()
    # toggle off 2 first bits
    data.setPosition(offset)

  var labelLen = data.readInt8()
  while labelLen != 0:
    if labelLen == -64:
      var jump = data.readInt8()
      labels.add(data.getName(jump))
      break
    else:
      labels.add(data.readStr(labelLen))
    labelLen = data.readInt8()
  result = labels.join(".")

  if offset > 0:
     data.setPosition(lastPos)
