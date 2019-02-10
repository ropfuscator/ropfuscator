.PHONY: clean directories all

MKDIR = mkdir -p

# Compiler vars
CC = clang
CFLAGS = -m32 -c -fomit-frame-pointer -fno-pie
IRFLAGS = -O0 -S -emit-llvm
ROPLIB_CFLAGS = -m32 -shared
ROPF_LLC = ropf-llc
ROPF_LLC_FLAGS = -march=x86

# Directories vars
OUT_DIR = bin
TMP_DIR = tmp
ROPLIB_SRCDIR = ..
OP_SRCDIR = ..
ROPLIB_RPATH = lib

# etc.
OP_NAME = op
ROPLIB_NAME = naive
ROPLIB_SRC = lib$(ROPLIB_NAME).c
APP_NAME = example5

all: directories $(OUT_DIR)/$(APP_NAME)

# Final ROPfuscated executable
$(OUT_DIR)/$(APP_NAME): $(TMP_DIR)/$(APP_NAME).s $(TMP_DIR)/$(OP_NAME).a $(ROPLIB_RPATH)/lib$(ROPLIB_NAME).so
	$(info --> Compiling the ROPfuscated executable)
	LD_RUN_PATH='$$ORIGIN/$(ROPLIB_RPATH)' gcc -m32 $(TMP_DIR)/$(APP_NAME).s $(TMP_DIR)/$(OP_NAME).a -lc -o $@ 
# ROP support library
$(ROPLIB_RPATH)/lib$(ROPLIB_NAME).so: $(ROPLIB_SRCDIR)/lib$(ROPLIB_NAME).c
	$(info --> Compiling support library)
	$(CC) $(ROPLIB_CFLAGS) $< -o $@

# LLVM compiler (the ROPfuscator MachineFunctionPass runs here)
$(TMP_DIR)/$(APP_NAME).s: $(TMP_DIR)/$(APP_NAME).ll
	$(info --> Generating machine code using LLVM compiler)
	$(ROPF_LLC) $(TMP_DIR)/$(APP_NAME).ll $(ROPF_LLC_FLAGS)

# Translation from C to LLVM IR
$(TMP_DIR)/$(APP_NAME).ll: $(APP_NAME).c
	$(info --> Generating LLVM IR from input file)
	$(CC) $(IRFLAGS) $< -o $@

# OPAQUE PREDICATE object file generation
$(TMP_DIR)/$(OP_NAME).o: $(OP_SRCDIR)/$(OP_NAME).c
	$(info --> Generating opaque predicate object file)
	$(CC) $< $(CFLAGS) -o $@ 

# Static library generation
$(TMP_DIR)/$(OP_NAME).a: $(TMP_DIR)/$(OP_NAME).o
	$(info --> Creating opaque predicate static library)
	ar rcs $@ $<

$(TMP_DIR):
	$(MKDIR) $(TMP_DIR)

$(ROPLIB_RPATH):
	$(MKDIR) $(ROPLIB_RPATH)

$(OUT_DIR):
	$(MKDIR) $(OUT_DIR)

directories: $(TMP_DIR) $(ROPLIB_RPATH) $(OUT_DIR)

clean:
	@-rm -r $(TMP_DIR) $(ROPLIB_RPATH) $(OUT_DIR) 2> /dev/null
