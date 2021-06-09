CTest for ROPfuscator
==============================

About
------------------------------

This directory contains test cases for ROPfuscator.
The tests are executed via CTest framework, provided by CMake.

Running Tests
------------------------------

On the ROPfuscator build directory, type

    ctest

You will see the following console output (for example):

    Test project .../build
          Start  1: test-testcase-example1-plain-build
     1/15 Test  #1: test-testcase-example1-plain-build ..................   Passed    0.20 sec
          Start  2: test-testcase-example1-ropfuscated-build
     2/15 Test  #2: test-testcase-example1-ropfuscated-build ............   Passed    0.19 sec
          Start  3: test-testcase-example1-plain-exec
     3/15 Test  #3: test-testcase-example1-plain-exec ...................   Passed    0.00 sec
       ....
          Start 15: test-testcase002-ropfuscated-result-compare
    15/15 Test #15: test-testcase002-ropfuscated-result-compare .........   Passed    0.01 sec
    
    100% tests passed, 0 tests failed out of 15
    
    Total Test time (real) =   1.21 sec


Adding Tests
------------------------------

1. Put the C code in `ropfuscator-extra/testcase/src/` directory.
2. Add test case name (base name of the `.c` file) and compile flags in `ropfuscator-extra/testcase/CMakeLists.txt`.
3. Run `ninja llc` (or whatever target) in the ROPfuscator build directory, to reload `CMakeLists.txt`.

Please note that every test case in this directory should meet the following criteria:

* It does not take command-line arguments.
* It writes its output to `stdout`.
  * If it does not output anything, comparison test will always succeed, thus cannot test if ROPfuscator preserves the semantics.
* If it is invoked multiple times, the outputs are the same.
  * If the output changes randomly, comparison test will fail.
* It exits with code 0.
  * Exit code other than 0 will be treated as failure of the test.

If any of the above conditions are not met, you should put your code in a separate directory and put custom `add_test(...)` directives in `CMakeLists.txt`.


Test Case Details
------------------------------

There are 5 test cases generated for each C source code:

1. `test-xxx-plain-build`: test if the plain binary is successfully built
2. `test-xxx-ropfuscated-build`: test if the ROPfuscated binary is successfully built
3. `test-xxx-plain-exec`: test if the plain binary runs without an error
4. `test-xxx-ropfuscated-exec`: test if the ROPfuscated binary runs without an error
5. `test-xxx-ropfuscated-result-compare`: test if the plain binary and the ROPfuscated binary output the same results to `stdout`

These test cases have dependencies; test case 3 depends on test case 1, test case 4 depends on test case 2, and test case 5 depends on test cases 1 and 2.

