
# Evaluation of ROPfuscator

This directory contains source code and scripts for evaluating ROPfuscator.

Each executable is named like: `eval.EXEC_NAME.CONFIG`

## configurations

See `ropfuscator-extra/configs`.

|Config name                         |ROP-based obfuscation|Opaque constant (algorithm)|Branch divergence (algorithm)|
|------------------------------------|---------------------|---------------------------|-----------------------------|
|`plain`                             |No                   |None                       |None                         |
|`roponly`                           |Yes                  |None                       |None                         |
|`opaque-dummy`                      |Yes                  |MOV (dummy)                |None                         |
|`opaque-multcomp`                   |Yes                  |MULTCOMP                   |None                         |
|`opaque-dummy-branch-addreg`        |Yes                  |MOV (dummy)                |ADDREG (max branch = 32)     |
|`opaque-dummy-branch-rdtsc`         |Yes                  |MOV (dummy)                |RDTSC  (max branch = 32)     |
|`opaque-dummy-branch-negstk`        |Yes                  |MOV (dummy)                |NEGSTK (max branch = 32)     |
|`opaque-dummy-branch-addreg-limit2` |Yes                  |MOV (dummy)                |ADDREG (max branch =  2)     |
|`opaque-dummy-branch-addreg-limit4` |Yes                  |MOV (dummy)                |ADDREG (max branch =  4)     |
|`opaque-dummy-branch-addreg-limit8` |Yes                  |MOV (dummy)                |ADDREG (max branch =  8)     |
|`opaque-dummy-branch-addreg-limit16`|Yes                  |MOV (dummy)                |ADDREG (max branch = 16)     |
|`opaque-multcomp-branch-addreg`     |Yes                  |MULTCOMP                   |ADDREG (max branch = 32)     |


## crackme

|Program name                 |Taken from                |Challenge goal                                |
|-----------------------------|--------------------------|----------------------------------------------|
|`defcon-quals-2016-baby-re`  |DEFCON CTF Qualifier 2016 |Find an input (from stdin) to print flag      |
|`defcon-quals-2017-magic`    |DEFCON CTF Qualifier 2017 |Find an input (from stdin) to print "sum is"  |
|`google-ctf-2018-gatekeeper` |Google CTF 2018           |Find an input (from stdin) to print "Correct" |
|`crackme1`                   |(ourselves)               |Find a command line argument to print "OK"    |
|`crackme2`                   |(ourselves)               |Find a command line argument to print "OK"    |

- build binary
  ```
  cmake ropfuscator-evaluation-crackme
  ```
- attack scripts \
  see `ropfuscator/evaluation/crackme/attack/`.
- run evaluation
  ```
  ropfuscator/evaluation/crackme/scripts/run-eval-robust-angr-orig.sh
  ropfuscator/evaluation/crackme/scripts/run-eval-robust-angr-ctf.sh
  ```

