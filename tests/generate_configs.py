import itertools
from enum import Enum

BOOL_VALUES = [True, False]
PERCENTAGE_VALUES = [0, 33, 66, 100]

class OpaquePredicateAlgorithm(Enum):
    MOV = "mov"
    R3SAT32 = "r3sat32"
    MULTCOMP = "multcomp"

class OpaquePredicateInputAlgorithm(Enum):
    CONST = "const"
    ADDREG = "addreg"
    RDTSC = "rdtsc"

def get_config(
        obfuscation_enabled: bool, 
        search_segment_for_gadget: bool,
        avoid_multiversion_symbol: bool,
        show_progress: bool,
        print_instr_stat: bool,
        rng_seed: bool,
        opaque_gadget_addresses_enabled: bool,
        gadget_addresses_obfuscation_percentage: int,
        opaque_predicates_enabled: bool,
        opaque_saved_stack_values_enabled: bool,
        opaque_immediate_operands_enabled: bool,
        opaque_immediate_operands_percentage: int,
        opaque_branch_targets_enabled: bool,
        opaque_branch_targets_percentage: int,
        opaque_predicates_algorithm: OpaquePredicateAlgorithm,
        opaque_predicates_input_algorithm: OpaquePredicateInputAlgorithm,
        contextual_opaque_predicates_enabled: bool
        ):

    return f"""
    [general]
    obfuscation_enabled = {obfuscation_enabled}
    search_segment_for_gadget = {search_segment_for_gadget}
    avoid_multiversion_symbol = {avoid_multiversion_symbol}
    show_progress = {show_progress}
    print_instr_stat = {print_instr_stat}
    {"rng_seed = 0123456789" if rng_seed else ""}

    [functions.default]
    obfuscation_enabled = {obfuscation_enabled}
    opaque_gadget_addresses_enabled = {opaque_gadget_addresses_enabled}
    gadget_addresses_obfuscation_percentage = {gadget_addresses_obfuscation_percentage}
    opaque_predicates_enabled = {opaque_predicates_enabled}
    opaque_saved_stack_values_enabled = {opaque_saved_stack_values_enabled}
    opaque_immediate_operands_enabled = {opaque_immediate_operands_enabled}
    opaque_immediate_operands_percentage = {opaque_immediate_operands_percentage}
    opaque_branch_targets_enabled = {opaque_branch_targets_enabled}
    opaque_branch_targets_percentage = {opaque_branch_targets_percentage}
    opaque_predicates_algorithm = {opaque_predicates_algorithm.value}
    opaque_predicates_input_algorithm = {opaque_predicates_input_algorithm.value}
    contextual_opaque_predicates_enabled = {contextual_opaque_predicates_enabled}
    """

def main():
    config_number = 0

    for bool_set in itertools.product(BOOL_VALUES, repeat=12):
        obfuscation_enabled,\
        search_segment_for_gadget, \
        avoid_multiversion_symbol,\
        show_progress,\
        print_instr_stat,\
        rng_seed,\
        opaque_gadget_addresses_enabled,\
        opaque_predicates_enabled,\
        opaque_saved_stack_values_enabled,\
        opaque_immediate_operands_enabled,\
        opaque_branch_targets_enabled,\
        contextual_opaque_predicates_enabled = bool_set
        
        for percentage_set in itertools.product(PERCENTAGE_VALUES, repeat=3):
            gadget_addresses_obfuscation_percentage, \
            opaque_immediate_operands_percentage, \
            opaque_branch_targets_percentage = percentage_set

            for op_algo in OpaquePredicateAlgorithm:
                for input_op_algo in OpaquePredicateInputAlgorithm:
                    with open(f"config_{config_number}.toml", "w") as f:                    
                        f.write(get_config(obfuscation_enabled, 
                            search_segment_for_gadget, \
                            avoid_multiversion_symbol, \
                            show_progress, \
                            print_instr_stat, \
                            rng_seed, \
                            opaque_gadget_addresses_enabled, \
                            gadget_addresses_obfuscation_percentage, \
                            opaque_predicates_enabled, \
                            opaque_saved_stack_values_enabled, \
                            opaque_immediate_operands_enabled, \
                            opaque_immediate_operands_percentage, \
                            opaque_branch_targets_enabled, \
                            opaque_branch_targets_percentage, \
                            op_algo, \
                            input_op_algo, \
                            contextual_opaque_predicates_enabled))
                    
                    config_number += 1

    return

if __name__ == "__main__":
    main()
