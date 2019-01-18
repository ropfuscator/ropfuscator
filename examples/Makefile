ROPLIB_RPATH=lib
ROPLIB_NAME=libnaive.so
OP_PATH=opaque_predicate
APP_NAME=example1

# Final ROPfuscated executable
bin/$(APP_NAME): tmp/$(APP_NAME).s $(OP_PATH)/bin/op.a
	$(info --> Compiling the ROPfuscated executable)
	LD_RUN_PATH='$$ORIGIN/$(ROPLIB_RPATH)' gcc tmp/$(APP_NAME).s $(OP_PATH)/bin/op.a -l:$(ROPLIB_NAME) -o $@ 

# LLVM compiler (the ROPfuscator MachineFunctionPass runs here)
tmp/$(APP_NAME).s: tmp/$(APP_NAME).ll
	$(info --> Generating machine code using LLVM compiler)
	llc tmp/$(APP_NAME).ll 

# Translation from C to LLVM IR
tmp/$(APP_NAME).ll: $(APP_NAME).c
	$(info --> Generating LLVM IR from input file)
	clang -O0 -S -emit-llvm $< -o $@

# OPAQUE PREDICATE \
  Object file generation
$(OP_PATH)/obj/op.o: $(OP_PATH)/src/op.c
	$(info --> Generating opaque predicate object file)
	gcc $< -o $@ -c -fomit-frame-pointer -fno-pie -no-pie

# Static library generation
$(OP_PATH)/bin/op.a: $(OP_PATH)/obj/op.o
	$(info --> Creating opaque predicate static library)
	ar rcs $@ $<

clean:
	rm tmp/* $(OP_PATH)/obj/* $(OP_PATH)/bin/* $(APP_NAME)

# ROP LIBRARY \
  In this PoC the dynamic library used by the ROPfuscated binary is \
  made up artificially with all the needed gadgets.					\
  This approach was chosen only to simplify the testing phase,  	\
  but an arbitrary library can be still be used.



