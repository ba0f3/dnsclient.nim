import endians, streams, strutils

const MAX_LABEL_LENGTH = 63
const MAX_NAME_LENGTH = 255

const TYPE_MASK = 0xC0'u8
type LabelType = enum
  TYPE_LABEL = 0x00'u8
  TYPE_EDNS0 = 0x40'u8
  TYPE_RESERVED = 0x80'u8
  TYPE_INDIR = 0xc0'u8

proc readTTL*(s: StringStream): int32 {.inline.} =
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

proc getName*(data: StringStream): string =
  var
    labels: seq[string]
    length: uint8
    offset: uint16
    kind: LabelType
    lastPos: int = 0
    lenLeft = MAX_NAME_LENGTH

  while true:
    length = data.readUint8()
    if length == 0: break
    kind = LabelType(length and TYPE_MASK)
    case kind
    of TYPE_INDIR:
      # length is first octet << 8 + last octet
      offset = (length.uint16 shl 8 + data.readUint8()) xor 0xC000'u16
      lastPos = data.getPosition()
      data.setPosition(offset.int)
      if data.atEnd():
        raise newException(ValueError, "Invalid compression label offset")
      if LabelType(data.peekUint8() and TYPE_MASK) == TYPE_INDIR:
        raise newException(ValueError, "Nested compression label is not supported")
      # we will get the label in next loop as TYPE_LABEL
    of TYPE_LABEL:
      if length.int > MAX_LABEL_LENGTH:
        raise newException(ValueError, "Label too long, max 63 got " & $length)
      dec(lenLeft, length.int + 1)
      if lenLeft <= 0:
        raise newException(ValueError, "Name too long")
      labels.add(data.readStr(length.int))
      # if next octet is zero, means and of labels
      # go back to last position and stop
      if data.peekUint8() == 0 and lastPos > 0:
        data.setPosition(lastPos)
        break # last label was INDIR, stop the loop
    else:
      #reversed
      break
  result = if labels.len == 1: labels[0] else: labels.join(".")

proc ipv4ToString*(ip: int32): string =
  let arr = cast[array[4, uint8]](ip)
  arr.join(".")

proc ipv6ToString*(ip6: array[16, uint8]): string =
  for i in 0..<8:
    result &= ":"
    result &= ip6[i * 2].toHex()
    result &= ip6[i * 2 + 1].toHex()
  result.removePrefix(":")
