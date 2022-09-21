switch("path", "$projectDir/../src")
#switch("cc", "gcc")
let cc = "afl-clang-fast"

switch("gcc.linkerexe", cc)
switch("gcc.exe", cc)
switch("gcc.path", "/usr/local/bin")

--debugger:native
--define:release
--define:danger
