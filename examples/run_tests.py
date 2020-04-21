import subprocess
import re
from os import listdir, remove
from os.path import isfile, join


def __example7_init_callback():
    with open("a.txt", "w") as f:
        f.write("earth is hexagonal")


def __example7_cleanup_callback():
    remove("a.txt")


BINARIES_DIR = "../build/bin"
BIN_NAME_RE = re.compile("example[0-9]+$")
CMDS = {
    "perf": ["perf", "stat", "-e",
             "branches,bus-cycles,cache-misses,cache-references,cycles,ref-cycles,instructions,task-clock"],
    "llvm-profdata": ["llvm-profdata", "show", "-all-functions", "-counts", "-ic-targets"]
}
TEST_INPUTS = {
    "example1": {
        "callbacks": [],
        "argv": [],
        "stdin": []
    },
    "example2": {
        "callbacks": [],
        "argv": [],
        "stdin": ["450 234\n"]
    },
    "example3": {
        "callbacks": [],
        "argv": [],
        "stdin": ["4 -2345 -593 4873 1234\n"]
    },
    "example4": {
        "callbacks": [],
        "argv": [],
        "stdin": ["4 8927 -532 213 4\n"]
    },
    "example5": {
        "callbacks": [],
        "argv": [],
        "stdin": []},
    # "example6": {
    #     "callbacks": [],
    #     "argv": ["/tmp/file.txt"],
    #     "stdin": ["1\n", "4\n", "palla\n", "1\n", "6\n",
    #             "pollo\n", "3\n", "6\n", "pillo\n", "2\n", "4\n"]
    # },
    "example7": {
        "callbacks": [__example7_init_callback, __example7_cleanup_callback],
        "argv": ["a.txt", "b.txt"],
        "stdin": []
    }
}


def TEST_LOG_TEMPLATE(bin1_name, bin2_name, perf1_out, llvm1_prof_out, bin1_out, perf2_out, llvm2_prof_out, bin2_out): return \
    """
{} | {} TEST RESULTS

##########
# {}
##########

{}

{}

PROGRAM OUTPUT:

{}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

##########
# {}
##########

{}

{}

PROGRAM OUTPUT:

{}
""".format(bin1_name, bin2_name, bin1_name, perf1_out, llvm1_prof_out, bin1_out, bin2_name, perf2_out, llvm2_prof_out, bin2_out)


def main():
    binaries_list = [f for f in listdir(BINARIES_DIR) if isfile(
        join(BINARIES_DIR, f)) and BIN_NAME_RE.match(f)]

    for b, ropb in zip(binaries_list, ["{}-ropfuscated".format(x) for x in binaries_list]):
        b_path = "{}/{}".format(BINARIES_DIR, b)
        ropb_path = "{}/{}".format(BINARIES_DIR, ropb)

        b_out, b_perf_out = perf_test(b_path, b)
        ropb_out, ropb_perf_out = perf_test(ropb_path, b)
        b_llvm_out, _ = extract_llvm_profdata(b, b)
        ropb_llvm_out, _ = extract_llvm_profdata(ropb, b)

        with open("{}-results.txt".format(b), "w") as f:
            f.write(TEST_LOG_TEMPLATE(b, ropb, b_perf_out, b_llvm_out,
                                      b_out, ropb_perf_out, ropb_llvm_out, ropb_out))

    return


def perf_test(test_bin_path, test_bin_name):
    cmd = CMDS["perf"][:]
    cmd.append(test_bin_path)

    return call_cmd(cmd, test_bin_path, test_bin_name)


def extract_llvm_profdata(test_bin_path, test_bin_name):
    cmd = CMDS["llvm-profdata"][:]
    cmd.append("{}.profdata".format(test_bin_path))

    return call_cmd(cmd, test_bin_path, test_bin_name)


def call_cmd(cmd, test_bin_path, test_bin_name):
    if test_bin_name in TEST_INPUTS:
        init_callbacks = [x for x in TEST_INPUTS[test_bin_name]
                          ["callbacks"] if "init" in x.__name__]
        cleanup_callbacks = [
            x for x in TEST_INPUTS[test_bin_name]["callbacks"] if "cleanup" in x.__name__]

        # INIT CALLBACKS
        for f in init_callbacks:
            print("[{}] Calling init callback \"{}\"".format(
                test_bin_name, f.__name__))
            f()

        print("Running \"{}\" on {}".format(" ".join(cmd), test_bin_path))

        p = subprocess.Popen(cmd,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             bufsize=1)

        if TEST_INPUTS[test_bin_name]["stdin"]:
            (out, err) = p.communicate(
                input=TEST_INPUTS[test_bin_name]["stdin"][0].encode('utf-8'))
        else:
            (out, err) = p.communicate()

        # CLEANUP CALLBACKS
        for f in cleanup_callbacks:
            print("[{}] Calling cleanup callback \"{}\"".format(
                test_bin_name, f.__name__))
            f()

        return (out.decode("utf-8"), err.decode("utf-8"))
    return (None, None)


if __name__ == "__main__":
    main()
