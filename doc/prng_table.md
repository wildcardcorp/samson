From https://rosettacode.org/wiki/Random_number_generator_(included) and personal research.

Popular languages: https://www.tiobe.com/tiobe-index/

Using https://www.tablesgenerator.com/markdown_tables.

| Language/Platform                        | PRNG(s)                                  |
|------------------------------------------|------------------------------------------|
| Bash                                     | LCG (Park and Miller '88)                |
| C#/VB .NET/Powershell                    | SLFG                                     |
| D                                        | MT19937/LCG                              |
| Dart                                     | MWC, See Javascript                      |
| Delphi                                   | LCG                                      |
| Elm/Typescript/CoffeeScript/Scratch      | See Javascript                           |
| Erlang/Elixir                            | Xoroshiro116+/Xorshift1024*/Xorshift116+ |
| FreeBSD /dev/random                      | Fortuna                                  |
| FreeBSD C                                | LCG (Park and Miller '88)                |
| GAP                                      | ALFG/MT19937                             |
| Go                                       | ALFG                                     |
| Java/Scala/Clojure/Groovy/Kotlin         | LCG                                      |
| Javascript/NodeJS                        | Xorshift128+                             |
| Julia                                    | MT19937                                  |
| Linux >=4.8 /dev/urandom                 | ChaCha20                                 |
| Linux C/C++                              | LCG/ALFG/MT19937                         |
| Lua                                      | Xorshift128+                             |
| Mac/iOS /dev/random                      | Yarrow (SHA1)                            |
| Matlab/Octave                            | MT19937                                  |
| OCaml                                    | LFSR/LFG                                 |
| OpenBSD >=5.1, <5.5 /dev/random          | ARC4                                     |
| OpenBSD >=5.5 /dev/random                | ChaCha20                                 |
| OpenBSD/NetBSD C                         | LCG                                      |
| Pascal                                   | MT19937                                  |
| Perl                                     | LCG                                      |
| PHP                                      | MT19937                                  |
| Python                                   | MT19937                                  |
| R                                        | MT19937                                  |
| Ruby                                     | MT19937                                  |
| Rust                                     | Xorshift128                              |
| SAS                                      | LCG                                      |
| Swift/Objective C                        | ARC4                                     |
| Tcl                                      | LCG                                      |
| Windows CNG                              | AES256-CTR (NIST SP 800-90A)             |