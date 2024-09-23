# Ghidra Python script to extract and reconstruct routes from decompiled Go binary
# This is a PoC challenge for evaluation of ChatGPT O1 model, not a fully functional Golang RE solution for the defined problem.
# But it works!
#
# @hkashfi, Sep 2024

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import re

def main():
    # Initialize Decompiler
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)

    # Get all functions in the binary
    function_manager = currentProgram.getFunctionManager()
    all_functions = function_manager.getFunctions(True)  # True for forward iterator

    routes = []

    # Regular expressions to match function calls
    method_assign_regex = re.compile(r'\*(\w+)\s*=\s*"(.*?)"\s*;')
    methods_call_regex = re.compile(r'.*?___Router__Methods\((.*?)\);')
    path_regex = re.compile(r'.*?___Route__addRegexpMatcher\((.*?)\);')

    # For each function, decompile and search for route registrations
    for func in all_functions:
        # Decompile the function
        decomp_results = decompile_function(decomp_interface, func)
        if not decomp_results:
            continue

        code_text = decomp_results.getDecompiledFunction().getC()
        lines = code_text.split('\n')

        method_var_map = {}  # Maps method variable names to method strings
        current_methods = []
        current_route_var = None

        for i, line in enumerate(lines):
            line = line.strip()
            # Match method assignments like: *extraout_RAX = "POST";
            method_assign_match = method_assign_regex.match(line)
            if method_assign_match:
                var_name = method_assign_match.group(1)
                method = method_assign_match.group(2)
                method_var_map[var_name] = method
                continue

            # Match Methods call: github_com_gorilla_mux___Router__Methods(...)
            methods_call_match = methods_call_regex.match(line)
            if methods_call_match:
                args = methods_call_match.group(1)
                arg_list = [arg.strip() for arg in args.split(',')]
                if len(arg_list) >= 2:
                    method_var = arg_list[1]
                    method = method_var_map.get(method_var, 'UNKNOWN')
                    current_methods = [method]
                continue

            # Match path registration: github_com_gorilla_mux___Route__addRegexpMatcher(...)
            path_match = path_regex.match(line)
            if path_match:
                args = path_match.group(1)
                arg_list = [arg.strip() for arg in args.split(',')]
                if len(arg_list) >= 2:
                    path_arg = arg_list[1]
                    path = extract_string_literal(path_arg)
                    # Store the route information
                    routes.append({
                        'methods': current_methods,
                        'path': path,
                        'function': func.getName()
                    })
                    # Reset current methods and route variable for next route
                    current_methods = []
                    current_route_var = None
                continue

    # Pretty-print the routes
    print("Extracted Routes:")
    for route in routes:
        methods = ', '.join(route['methods'])
        path = route['path']
        func_name = route['function']
        print("Function: {}, Methods: {}, Path: {}".format(func_name, methods, path))

def decompile_function(decomp_interface, func):
    try:
        results = decomp_interface.decompileFunction(func, 0, ConsoleTaskMonitor())
        if results.decompileCompleted():
            return results
    except:
        pass
    return None

def extract_string_literal(arg):
    # Extracts the string literal from an argument, handling quotes
    match = re.match(r'"(.*?)"', arg)
    if match:
        return match.group(1)
    else:
        return arg

main()
