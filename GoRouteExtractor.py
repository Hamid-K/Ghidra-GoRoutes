# GoRouteExtractor.py
"""
Ghidra script to automatically analyze Golang binaries using Gorilla mux library.
It will identify functions that define and handle routes, as well as the path and parameters of endpoints.
This is a work in progress and half-functional version.

To-do: Implement a generic way to extract handler function name rather than relying on strings as it is now.
To-do: Implement detection for other common libraries.
To-do: Complete rewrite to avoid relyiing on the decompiler.

@hkashfi
"""

import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

DEBUG = False  # Set to True for detailed debug output

def debug_print(message):
    if DEBUG:
        print(message)

def find_functions_calling_addRegexpMatcher_or_PathPrefix():
    """
    Find all functions that call the addRegexpMatcher or PathPrefix methods in the program.
    """
    symbol_table = currentProgram.getSymbolTable()
    target_funcs = []
    matcher_syms = []

    symbol_iterator = symbol_table.getAllSymbols(True)
    for sym in symbol_iterator:
        sym_name = sym.getName()
        if sym_name.endswith("addRegexpMatcher") or sym_name.endswith("PathPrefix"):
            matcher_syms.append(sym)

    if not matcher_syms:
        debug_print("[DEBUG] Could not find symbols for addRegexpMatcher or PathPrefix")
        return target_funcs

    debug_print("[DEBUG] Found symbols for addRegexpMatcher or PathPrefix:")
    for sym in matcher_syms:
        debug_print(" - " + sym.getName())

    for matcher_sym in matcher_syms:
        matcher_addr = matcher_sym.getAddress()
        references = getReferencesTo(matcher_addr)
        for ref in references:
            if ref.getReferenceType().isCall():
                caller_func = getFunctionContaining(ref.getFromAddress())
                if caller_func and caller_func not in target_funcs:
                    target_funcs.append(caller_func)
                    debug_print("[DEBUG] Found function calling {}: {}".format(matcher_sym.getName(), caller_func.getName()))

    return target_funcs

def extract_handler_function_from_decompiled_code(decompiled_code, func_name):
    """
    Extract the handler function name from the decompiled code, using regex to identify patterns like
    (code *)&PTR_backend/tacacs.addTacacsService_00bbde88
    :param decompiled_code: Decompiled code as a string
    :param func_name: Name of the function being analyzed
    :return: Extracted handler function names
    """
    handler_pattern = r'&PTR_([a-zA-Z0-9_/\.]+)'  # Regex to capture handler function names
    debug_print("[DEBUG] Decompiled code for {}:\n{}".format(func_name, decompiled_code))

    matches = re.findall(handler_pattern, decompiled_code)
    if matches:
        return matches
    else:
        debug_print("[DEBUG] No handler functions found in function: {}".format(func_name))
        return []

def extract_path_and_prefix(decompiled_code, func_name):
    """
    Extract the path and prefix from the decompiled code for PathPrefix and addRegexpMatcher calls.
    :param decompiled_code: Decompiled code as a string
    :param func_name: Name of the function being analyzed
    :return: Extracted prefixes and paths
    """
    prefix_pattern = r'PathPrefix\([^,]+,\s*"([^"]+)"'
    regexp_pattern = r'addRegexpMatcher\([^,]+,\s*"([^"]+)"'

    debug_print("[DEBUG] Decompiled code for {}:\n{}".format(func_name, decompiled_code))

    prefixes = re.findall(prefix_pattern, decompiled_code)
    route_paths = re.findall(regexp_pattern, decompiled_code)

    if not prefixes:
        prefixes = ["<unknown_prefix>"]
    if not route_paths:
        route_paths = ["<unknown_path>"]

    return prefixes, route_paths

def analyze_router_function(func):
    """
    Analyze a router function to extract its paths, prefixes, and backend handler functions.
    """
    monitor = ConsoleTaskMonitor()
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = decompiler.decompileFunction(func, 60, monitor)

    if not result.decompileCompleted():
        debug_print("[DEBUG] Decompilation failed for function: {}".format(func.getName()))
        return []

    decompiled_code = result.getDecompiledFunction().getC()
    prefixes, route_paths = extract_path_and_prefix(decompiled_code, func.getName())
    handler_funcs = extract_handler_function_from_decompiled_code(decompiled_code, func.getName())

    return prefixes, route_paths, handler_funcs

def print_defined_routes():
    """
    Find functions calling addRegexpMatcher or PathPrefix, extract routes and handler functions, and print the results.
    """
    funcs = find_functions_calling_addRegexpMatcher_or_PathPrefix()
    print("Defined Routes:")

    for func in funcs:
        func_name = func.getName()

        prefixes, route_paths, handler_funcs = analyze_router_function(func)

        for prefix in prefixes:
            for route_path in route_paths:
                for handler in handler_funcs:
                    print("Prefix: {},  {}\t\t ,handler: {}\t\t,Router: {}".format(prefix, route_path, handler, func_name))

def main():
    print_defined_routes()

if __name__ == "__main__":
    main()
