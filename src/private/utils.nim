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

proc getBits(data: auto, offset: int, bits = 1): int =
  let mask = ((1 shl bits) - 1) shl offset
  result = (data.int and mask) shr offset

proc getName*(data: StringStream): string =
  var labels: seq[string]
  while true:
    let
      length  = data.readUint8()
      magic = length.getBits(6, 2)
    if magic == 3:
      data.setPosition(data.getPosition() - 1)
      let offset = int(data.readShort() xor 0xC000)
      let currentPosition = data.getPosition()
      data.setPosition(offset)
      labels.add(data.getName())
      data.setPosition(currentPosition)
      break
    elif length.int > 0:
        labels.add(data.readStr(length.int))
    else:
      break
  result = labels.join(".")

proc ipv4ToString*(ip: int32): string =
  var arr = cast[array[4, uint8]](ip)
  arr.join(".")
