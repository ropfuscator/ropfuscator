# ROPfuscator Obfuscation Algorithm

## Algorithm overview

- ROP Transformation
  - Algorithm: Convert each instruction into one or more ROP gadgets, and translate the entire code to ROP chains.
  - Robustness: This transformation makes it hard for normal disassemblers and decompilers to recover the original code.
  Weakness: Several techniques have been proposed to reverse ROP chains, and ROP transformation does not protect those techniques.
- Opaque Predicate Insertion
  - Algorithm: Translate ROP gadget address(es) and stack pushed values into opaque constants, which are a composition of multiple opaque predicates.
  - Robustness: Opaque constants make it hard to statically infer transformed values, i.e., ROP gadget addresses and stack-based values. Therefore, it breaks static analysis to detect ROP gadgets and reverse them into original instructions. Also, input to opaque predicate implementation is crafted to include user-supplied values (only known at run-time), making DSE diverge when it tries to resolve execution paths.
  - Weakness: Though it is resistant to DSE, it is not robust against instruction tracing based reversing techniques.
- Instruction Hiding
  - Instead of applying ROP transformation to all instructions, pick up some original instructions before ROP transformation and interleave them with the opaque predicate instructions.
  - Robustness: This will make some of the original instructions hard to be identified in the execution trace, as they are hidden in large opaque predicate execution trace. The decompiler’s output would be corrupted even if a small part of the instruction trace is not available.
  - Weakness: Non-hidden instructions can be revealed in instruction trace, and the protection is not complete. Hidden instructions are not protected by ROP or opaque predicate and may be easier to be analyzed.

## Robustness and Performance Overhead

ROPfuscator deals with the following threat model:

- Decompilers
- Static ROP chain recovery
- Dynamic symbolic execution (DSE)
- Dynamic ROP chain recovery

There is a trade-off between robustness and performance. Generally, if more obfuscation layers are applied, the program is more robust and runs more quickly, and has a larger size.

| algorithm |    |    | Threat |      |     |      | Performance |       |
|-----------|----|----|--------|------|-----|------|-------------|-------|
| ROP       | OP | IH | Dec    | SROP | DSE | DROP | Time        | Size  |
| -         | -  | -  | -      | -    | -   | -    | 1x          | 1x    |
| X         | -  | -  | X      | -    | -   | -    | 200x        | 15x   |
| X         | X  | -  | X      | X    | X   | -    | 4000x       | 2500x |
| X         | X  | X  | X      | X    | X   | X    | 3000x       | 2000x |

(ROP = ROP Transformation, OP = Opaque predicate insertion, IH = Instruction Hiding, Dec = Decompilers, SROP = Static ROP chain recovery, DSE = Dynamic symbolic execution, DROP = Dynamic ROP chain recovery)

These obfuscation methods can be chosen per function; it means that ROPfuscator can be configured to obfuscate sensitive functions with a more robust algorithm, while the other parts with a weaker algorithm to meet both robustness and performance requirements.

## Algorithm details

- ROP Transformation
  - Gadgets are automatically extracted from `libc` or from a custom library according to configuration.
  - Gadget addresses are referenced using **symbol anchoring**: each gadget is referenced using a random symbol within the provided library and its offset from it. Since symbol addresses are automatically resolved at run-time by the dynamic loader (`ld`), we can guarantee to reach the wanted gadget even if the library is mapped in memory at a non-static address. This makes ROPfuscator work well with ASLR. It also avoids symbol conflict by excluding symbols from other libraries (based on configuration) and the obfuscated program itself.
  - **Data-flow analysis**: in the case of a scratch register where to compute temporary values, only registers that don’t hold valuable data are used.
  - **Gadget generalization** through the **Xchg graph** allows parametrizing gadget instruction operands, giving the possibility to re-use the same gadgets but with different operands. This way, we ensure that instructions are correctly obfuscated even if the number of extracted gadgets is very restricted.
  - Supported instructions: `mov`, `add`, `sub`, `cmp`, `call`, `jmp`, `je` and many more instructions are supported; obfuscation coverage is about 60-80% with typical programs (optimization option `-O0`).
- Opaque Predicates
  - Using **opaque constants** to obfuscate gadget addresses, immediate operands and branch targets against static analysis
  - Supported opaque constant algorithms: Integer factorization-based, Random 3SAT-based, dummy
    - Integer factorization-based (`multcomp`) [recommended]: concatenate 32 outputs from opaque predicates. Each opaque predicate takes 2 (32-bit) input values, multiplies them, and compares the generated (64-bit) value to a 64-bit prime value. The opaque predicate always returns 0 (to get 1, negate the result).
    - Random 3-SAT based (`r3sat32`): concatenate 32 outputs from opaque predicates. Each opaque predicate takes a 32bit value, interprets each bit as a boolean variable, and tests a 3CNF formula. The 3CNF formula is large enough and thus unsatisfiable with a probability nearly equal to 1. This means that the opaque predicate returns almost always 0. The opaque predicate may generate an incorrect output in minimal possibility (when the clause is satisfiable, and the random value is the satisfiable input); if this is not acceptable, this opaque predicate should not be used.
    - Dummy algorithm (`mov`): This is not an “opaque” predicate - it just outputs the constant using `mov` instruction. This is not meant for production use but only for testing opaque constant interface.
  - Input generation strategy: there are several strategies to generate inputs to opaque predicates. These inputs are meant to be random or not predictable statically, hinder program analysis techniques such as DSE (DSE is expected to treat these inputs as “symbolic” values, which causes divergence in exploration). Algorithms include:
    - **Mixture of general-purpose registers** (`addreg`): use register values (highly possibly include user-input values) as opaque predicate inputs, which massively slows down dynamic symbolic execution (DSE) analysis. It computes `eax`+`ebx`+`ecx`+`edx`+`edi`+`esi`.
    - Use performance counter (`rdtsc`): use the result of `rdtsc` instruction, which is the clock cycle timestamp value (only known at run time).
    - Dummy implementation (`const`): use a constant random value.
  - **Mixture of invariant and contextual opaque predicates**: use contextual opaque predicate (output changes based on input values) to avoid opaque predicate identification attack by pattern matching
    - This modifies the above opaque constant algorithm such that the input is sometimes true and the result is opposite - details explained below:
    - Integer factorization-based (`multcomp`): An invariant opaque predicate takes two 32-bit random inputs and compares the multiplication result to a constant 64-bit prime number and always generates 0. On the other hand, a contextual opaque predicate compares the multiplication of two input values with the multiplication of two 32-bit prime numbers; it generates 1 for those two crafted values and generates 0 otherwise. This kind of contextual opaque predicates are used in conjunction with invariant opaque predicates to generate an opaque constant.
    - Random 3-SAT based (`r3sat32`): An invariant opaque predicate uses an unsatisfiable 3CNF formula to generate 0 regardless of input. On the other hand, a contextual opaque predicate uses a satisfiable 3CNF formula; it generates 1 for the satisfying input and 0 for other inputs. This kind of contextual opaque predicates are used in conjunction with invariant opaque predicates to generate an opaque constant.
  - **Stack mangling**: using constants saved on the stack as opaque predicate input to avoid easy analysis of opaque predicates
- Opaque predicates - **branch divergence**
  - Note: this algorithm is not discussed in the paper.
  - This is an experimental feature to invoke one of the equivalent gadgets randomly.
  - Typically, there are several equivalent ROP gadgets in the same binary (e.g., there can be multiple `pop edx; ret` gadgets, and there can be `push eax; ret` or `jmp eax` which are almost equivalent). Usually, ROPfuscator statically chooses one of the equivalent gadgets randomly and push the gadget address. When the branch divergence is used, ROPfuscator dynamically chooses one of the equivalent gadgets randomly. The execution path will diverge by choosing from multiple gadgets (at different addresses) at run-time. This makes some analysis with execution path tracking (such as DSE) infeasible to trace paths.
  - Formally speaking, branch divergence computes `y = f(x)`, where `y’ is the gadget address and `x` is a run-time random value. `f` is crafted such that the `y’ falls into a specific set of values (possible gadget addresses) based on `x`, whatever the value of `x` is. For example, if possible gadget addresses are `0x8040123`, `0x8080456`, `0x8040789`, then `f` should generate either one of these values from an arbitrary 32-bit value.
  - In the current implementation, the above `f` is implemented as a composition of the following steps:
    - (1) Random input generation: generate random `x` at run-time.
    - (2) Selection of random constants based on random input: `r = selector(x, random constants)` where `random constants` is determined at compile-time, and `selector` randomly selects one of possible values of `random constants` depending on `x` at run-time.
    - (3) Adjusting random constants to desired values: `y = adjustor(r, [random constants -> possible gadget addresses])` where
    - To summarise, it is implemented as: `y = adjustor(selector(x, random constants), [random constants -> possible gadget addresses])`
  - Algorithm configuration
    - The (1) input value generation algorithm and the (2) selection algorithm can be configured by the `branch_divergence_algorithm` option.
    - Configuration is in the format of `generator+selector`. For example, `"addreg+mov"` will use (1) input generation algorithm `addreg` and (2) selection algorithm `mov`.
  - (1) Random input generation algorithm
    - `” addreg”`: the branch is taken based on `eax`+`ebx`+`ecx`+`edx` (+ random constant).
    - `” rdtsc”`: the branch is taken based  on `rdtsc` instruction result (current CPU clock timestamp)
    - `” negativestack”`: the branch is taken based on `[esp-n]` where `n` is a random constant between 8 and 128 (multiples of 4).
  - (2) Selection algorithm
    - `mov`: each random constant is allocated in a leaf of a binary decision diagram and is chosen based on its input value (bits). As of now, this is the only available algorithm.
  - (3) Adjusting algorithm
    - This maps pre-generated random constants to gadget addresses (more precisely, gadget offsets from an anchor symbol). This algorithm is carefully designed (though not proven) so that the algorithm does not reveal the result value without input, nor the possible input value itself. If it is supplied with an unexpected value, it will generate a bogus value, which will be eventually interpreted as a gadget address and causes a crash.
    - The actual algorithm uses linear mapping with matrix multiplication. The basic idea is that, if we want to map `[x1 -> y1, x2 -> y2]`, then we create a formula `y1 = a*x1 + b` and `y2 = a*x2 + b` and compute `a` and `b`. This can be represented as `[y1,y2] = [[x1,1],[x2,1]]*[a,b]`, and can be solved by matrix inverse (mod `2^32`). That is, we can first compute `M=[[x1,1],[x2,1]]^-1 mod 2^32` and compute `[a,b] = M*[y1,y2] mod 2^32`.
    - To deal with 3 or more variable case, we need to introduce a non-linear conversion; we use right-shift for this purpose (note: if all values are even, right-shift is linear; otherwise, it will be non-linear). For example, if we want to map `[x1 -> y1, x2 -> y2, x3 -> y3]`, then we create a formula `y1 = a*x1 + b*(x1>>1) + c`, etc. This can be represented as `[y1,y2,y3] = [[x1,x1>>1,1],[x2,x2>>1,1],[x3,x3>>1,1]]*[a,b,c]`. This can be also solved by computing modular matrix inverse.
    - It is often the case that we cannot find a suitable matrix. In that case, we try to shift the `x1`..`xk` with a constant value.
    - If we cannot find an inverse matrix, in the end, we use a divide-and-conquer strategy: split the vector `x`, `y’ in smaller vectors and repeat the above algorithm.
    - Currently, this algorithm is hard-coded and is not configurable.
  - Note: since its nature, all possible branches in this mechanism are valid; therefore, it is not an effective countermeasure against concrete execution tracing (tracing only one path).
- Instruction Hiding
  - Pick up some instructions and embed them into insertion points in opaque predicates.
  - **Dummy code insertion**: to avoid identifying hidden code, it inserts dummy instructions to other insertion points. If the stack mangling is used in opaque predicates, it also tries to modify stack-saved constants to intertwine dummy code with opaque predicate semantics so that it is even harder to analyze.

### Algorithm configuration

See also: [usage.md](./usage.md)

Obfuscation algorithms can be switched on/off on a per-function basis. The configuration file provides several options to control the algorithms for each function.

- ROP Transformation
  - Can be switched on/off by `obfuscation_enabled` option (Note: if ROP transformation is off, other algorithms cannot be applied)
  - Gadget extraction options
    - The library path where gadgets extraction can be controlled globally with `custom_library_path` option.
    - To avoid library version confusion, the library SHA1 hash can be specified with `library_hash_sha1` option.
    - Gadget search is done in either ELF executable segments or ELF code sections. Generally, we can find more gadgets in executable segments since segments include a broader memory region than code sections (e.g., read-only data can be put into executable segments). This behavior can be controlled by `search_segment_for_gadget` option (true: use segments, false: use sections)
    - The gadget locations will be computed by “anchor” symbols to deal with ASLR. There are several options for picking up “anchor” symbols.
          There can be symbol conflict. Other library paths (to avoid symbol conflict) can be specified in “option.
- Opaque predicates
  - Can be switched on/off by `opaque_predicates_enabled` option (Note: if opaque predicates are off, branch divergence and instruction hiding cannot be turned on)
  - Algorithm can be configured using `opaque_predicates_algorithm` option.
  - Contextual opaque predicates can be enabled by setting `opaque_predicate_use_contextual` to true (it is true by default). If this option is set to false, only invariant opaque predicates are used.
  - Mangling stack saved values: This feature stores register values and statically generated random constants onto the stack in random order and uses those stack values in opaque predicate computation. This can be turned on/off using `obfuscate_stack_saved_values` option.
- Opaque predicates - branch divergence
  - Can be switched on/off by `branch_divergence_enabled` option.
  - Input value generation algorithm + selection algorithm can be configured by `branch_divergence_algorithm` option.
    - `"addreg+mov"`: the branch is taken based on `eax`+`ebx`+`ecx`+`edx` (+ random constant).
    - `"rdtsc+mov"`: the branch is taken based  on `rdtsc` instruction result (current CPU clock timestamp)
    - `” negativestack+mov”`: the branch is taken based on `[esp-n]` where `n` is a random constant between 8 and 128 (multiples of 4).
- Instruction hiding
  - Can be switched on/off by `opaque_stegano_enabled`.
