# Package

version       = "0.3.0"
author        = "Huy Doan"
description   = "Simple DNS Client & Library"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @["dnsclient"]
skipDirs      = @["fuzz", "tests"]

# Dependencies

requires "nim >= 0.20.0"
