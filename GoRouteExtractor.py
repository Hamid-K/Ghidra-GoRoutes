# GoRouteExtractor.py
"""
Ghidra script to automatically analyze Golang binaries using Gorilla mux library.
It will identify functions that define and handle routes, as well as the path and parameters of endpoints.
This is a work in progress and half-functional version.

@hkashfi
"""

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp

DEBUG = False  # Set to True for detailed debug output

def debug_print(message):
    if DEBUG:
        print(message)

def find_functions_calling_addRegexpMatcher():
    """
    Find all functions that call the addRegexpMatcher method in the program.
    """
    symbol_table = currentProgram.getSymbolTable()
    target_funcs = []
    addRegexpMatcher_syms = []

    symbol_iterator = symbol_table.getAllSymbols(True)
    for sym in symbol_iterator:
        sym_name = sym.getName()
        if sym_name.endswith("addRegexpMatcher"):
            addRegexpMatcher_syms.append(sym)

    if not addRegexpMatcher_syms:
        debug_print("[DEBUG] Could not find symbol for addRegexpMatcher")
        return target_funcs

    debug_print("[DEBUG] Found symbols for addRegexpMatcher:")
    for sym in addRegexpMatcher_syms:
        debug_print(" - " + sym.getName())

    for addRegexpMatcher_sym in addRegexpMatcher_syms:
        addRegexpMatcher_addr = addRegexpMatcher_sym.getAddress()
        references = getReferencesTo(addRegexpMatcher_addr)
        for ref in references:
            if ref.getReferenceType().isCall():
                caller_func = getFunctionContaining(ref.getFromAddress())
                if caller_func and caller_func not in target_funcs:
                    target_funcs.append(caller_func)
                    debug_print("[DEBUG] Found function calling addRegexpMatcher: " + caller_func.getName())

    return target_funcs

# Adjusted regex pattern to capture the second parameter for PathPrefix and addRegexpMatcher
prefix_pattern = r'PathPrefix\([^,]+,\s*"([^"]+)"'
regexp_pattern = r'addRegexpMatcher\([^,]+,\s*"([^"]+)"'

def extract_prefix_from_decompiled_code(code, func_name):
    """
    Extract the prefix path from the decompiled code for PathPrefix calls.
    :param code: Decompiled code as a string
    :param func_name: Name of the function being analyzed
    :return: Extracted prefix path or None if not found
    """
    debug_print("[DEBUG] Decompiled code for {}:\n{}".format(func_name, code))
    matches = re.findall(prefix_pattern, code)
    if matches:
        return matches  # Return the found prefixes
    else:
        debug_print("[DEBUG] No prefix found in function: {}".format(func_name))
        return ["<unknown_prefix>"]

def extract_route_from_decompiled_code(code, func_name):
    """
    Extract the route path from the decompiled code for addRegexpMatcher calls.
    :param code: Decompiled code as a string
    :param func_name: Name of the function being analyzed
    :return: Extracted route paths or None if not found
    """
    matches = re.findall(regexp_pattern, code)
    if matches:
        return matches  # Return the found routes
    else:
        debug_print("[DEBUG] No route found in function: {}".format(func_name))
        return []

def analyze_function_for_routes(func):
    """
    Analyze a given function to extract route paths and their associated prefixes.
    """
    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = decompiler.decompileFunction(func, 60, monitor)

    if not result.decompileCompleted():
        debug_print("[DEBUG] Decompilation failed for function: {}".format(func.getName()))
        return []

    decompiled_code = result.getDecompiledFunction().getC()

    routes = []
    prefixes = extract_prefix_from_decompiled_code(decompiled_code, func.getName())
    route_paths = extract_route_from_decompiled_code(decompiled_code, func.getName())

    # Combine prefixes and route paths, and return
    for route_path in route_paths:
        for prefix in prefixes:
            routes.append((route_path, func.getName(), prefix))

    return routes

def print_defined_routes():
    """
    Find functions calling addRegexpMatcher and print their defined routes along with handler and router information.
    """
    funcs = find_functions_calling_addRegexpMatcher()
    print("Defined Routes:")

    for func in funcs:
        func_name = func.getName()

        routes = analyze_function_for_routes(func)
        if routes:
            for route_path, router_func_name, prefix in routes:
                print(" - {} ,handler: <unknown>, Router: {}, Prefix: {}".format(route_path, router_func_name, prefix))
        else:
            debug_print("[DEBUG] No routes found in function: {}".format(func_name))

def main():
    print_defined_routes()

if __name__ == "__main__":
    main()
