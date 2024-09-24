# GoRouteExtractor.py
"""
Ghidra script to automatically analyze Golang binaries using Gorilla mux library.
It will identify functions that define and handle routes, as well as the path and parameters of endpoints.
This is a work in progress and half-functional version.

@hkashfi

"""


from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import StringDataType

# === Configuration ===
DEBUG = True  # Set to True to enable debug logging

def debug_print(message):
    """
    Prints debug messages if DEBUG is enabled.
    """
    if DEBUG:
        print(message)

def find_register_routes_functions():
    """
    Find functions that likely register routes by containing 'RegisterRoutes' in their name.
    """
    symbol_table = currentProgram.getSymbolTable()
    func_manager = currentProgram.getFunctionManager()
    register_routes_funcs = []
    all_funcs = func_manager.getFunctions(True)
    for func in all_funcs:
        func_name = func.getName()
        if "RegisterRoutes" in func_name:
            register_routes_funcs.append(func)
            debug_print("[DEBUG] Found potential route registration function: " + func_name)
    return register_routes_funcs

def find_functions_calling_addRegexpMatcher():
    """
    Find all functions that call addRegexpMatcher, excluding those already identified as RegisterRoutes.
    """
    symbol_table = currentProgram.getSymbolTable()
    target_funcs = []

    # Find all symbols that end with 'addRegexpMatcher'
    addRegexpMatcher_syms = []
    symbol_iterator = symbol_table.getAllSymbols(True)
    for sym in symbol_iterator:
        if sym.getSymbolType() == SymbolType.FUNCTION:
            sym_name = sym.getName()
            if sym_name.endswith("addRegexpMatcher"):
                addRegexpMatcher_syms.append(sym)

    if not addRegexpMatcher_syms:
        debug_print("[DEBUG] Could not find symbol for addRegexpMatcher")
        return target_funcs

    debug_print("[DEBUG] Found symbols for addRegexpMatcher:")
    for sym in addRegexpMatcher_syms:
        debug_print(" - " + sym.getName())

    # Find functions that call any of the addRegexpMatcher symbols
    for addRegexpMatcher_sym in addRegexpMatcher_syms:
        addRegexpMatcher_addr = addRegexpMatcher_sym.getAddress()
        references = getReferencesTo(addRegexpMatcher_addr)
        for ref in references:
            if ref.getReferenceType().isCall():
                caller_func = getFunctionContaining(ref.getFromAddress())
                if caller_func and caller_func not in target_funcs:
                    # Exclude functions already identified as RegisterRoutes
                    if "RegisterRoutes" not in caller_func.getName():
                        target_funcs.append(caller_func)
                        debug_print("[DEBUG] Found function calling addRegexpMatcher: " + caller_func.getName())
    return target_funcs

def analyze_functions(funcs):
    """
    Analyze functions to extract route information.
    """
    all_routes = []
    for func in funcs:
        debug_print("[DEBUG] Analyzing function: " + func.getName())
        routes = extract_routes_from_function(func)
        all_routes.extend(routes)
    return all_routes

def analyze_register_routes_functions(funcs):
    """
    Analyze RegisterRoutes functions to extract route information.
    """
    all_routes = []
    for func in funcs:
        debug_print("[DEBUG] Analyzing route registration function: " + func.getName())
        routes = extract_routes_from_function(func)
        all_routes.extend(routes)
    return all_routes

def extract_routes_from_function(func):
    """
    Extract routes from a function by looking for calls to addRegexpMatcher.
    """
    monitor = ConsoleTaskMonitor()
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)
    res = decomp_interface.decompileFunction(func, 240, monitor)  # Increased timeout for larger functions
    if not res.decompileCompleted():
        print("[ERROR] Decompilation failed for function: " + func.getName())
        return []

    high_func = res.getHighFunction()
    if high_func is None:
        print("[ERROR] HighFunction is None for function: " + func.getName())
        return []

    routes = []
    pcode_ops = list(high_func.getPcodeOps())
    for op in pcode_ops:
        if op.getOpcode() == PcodeOp.CALL:
            called_func_addr = op.getInput(0).getAddress()
            called_func_name = get_function_name_at(called_func_addr)
            if "addRegexpMatcher" in called_func_name:
                route_pattern = get_route_pattern_from_call(op, high_func)
                if route_pattern == "<unknown_path>":
                    continue  # Skip routes without a valid path
                methods = find_methods_for_route(op, high_func)
                handler = find_handler_for_route(op, high_func)
                route_info = {
                    'path': route_pattern,
                    'methods': methods,
                    'handler': handler,
                    'defined_in': func.getName()
                }
                debug_print("[DEBUG] Found route: " + str(route_info))
                routes.append(route_info)
    return routes

def get_route_pattern_from_call(call_op, high_func):
    """
    Extract the route pattern from the addRegexpMatcher call.
    Iterate through all inputs to find a string or follow references.
    """
    inputs = call_op.getInputs()
    for i, varnode in enumerate(inputs):
        route_pattern = get_string_from_varnode(varnode, high_func)
        if route_pattern != "<unknown_string>":
            debug_print("[DEBUG] Found string in input {}: {}".format(i, route_pattern))
            return route_pattern
    debug_print("[DEBUG] addRegexpMatcher call does not have a resolvable string argument.")
    return "<unknown_path>"

def get_string_from_varnode(varnode, high_func, visited=None):
    """
    Attempt to retrieve a string from a Varnode.
    """
    if visited is None:
        visited = set()
    if varnode in visited:
        debug_print("[DEBUG] Already visited varnode: " + str(varnode))
        return "<unknown_string>"
    visited.add(varnode)

    if varnode.isAddress():
        addr = varnode.getAddress()
        string_data = getDataAt(addr)
        if string_data is not None and string_data.isDefined() and isinstance(string_data.getDataType(), StringDataType):
            try:
                return string_data.getValue().strip('"')
            except UnicodeEncodeError:
                debug_print("[DEBUG] UnicodeEncodeError while decoding string at address: " + str(addr))
                return "<unknown_string>"
        else:
            debug_print("[DEBUG] No string data at address: " + str(addr))
    elif varnode.isConstant():
        addr = toAddr(varnode.getOffset())
        string_data = getDataAt(addr)
        if string_data is not None and string_data.isDefined() and isinstance(string_data.getDataType(), StringDataType):
            try:
                return string_data.getValue().strip('"')
            except UnicodeEncodeError:
                debug_print("[DEBUG] UnicodeEncodeError while decoding string at constant address: " + str(addr))
                return "<unknown_string>"
        else:
            debug_print("[DEBUG] No string data at constant address: " + str(addr))
    else:
        # Attempt to resolve the varnode through its defining operation
        defining_op = varnode.getDef()
        if defining_op:
            opcode = defining_op.getOpcode()
            if opcode == PcodeOp.COPY:
                input_varnode = defining_op.getInput(0)
                return get_string_from_varnode(input_varnode, high_func, visited)
            elif opcode == PcodeOp.SUBPIECE:
                input_varnode = defining_op.getInput(0)
                return get_string_from_varnode(input_varnode, high_func, visited)
            elif opcode == PcodeOp.PTRADD:
                base_varnode = defining_op.getInput(0)
                offset_varnode = defining_op.getInput(1)
                base_address = base_varnode.getAddress()
                if base_address:
                    handler_address = base_address.add(offset_varnode.getOffset())
                    func = getFunctionAt(handler_address)
                    if func:
                        debug_print("[DEBUG] Resolved handler at computed address {}: {}".format(handler_address, func.getName()))
                        return func.getName()
                    else:
                        debug_print("[DEBUG] No function found at computed handler address: " + str(handler_address))
            elif opcode == PcodeOp.CALL:
                # Handle cases where strings are returned from function calls
                return "<unknown_string>"
            else:
                # For any other opcode, attempt to get the mnemonic
                try:
                    opcode_name = PcodeOp.getMnemonic(opcode)
                except Exception as e:
                    opcode_name = "<unknown_opcode>"
                debug_print("[DEBUG] Unhandled opcode in string resolution: " + opcode_name)
        else:
            debug_print("[DEBUG] No defining operation for varnode: " + str(varnode))
    return "<unknown_string>"

def find_methods_for_route(call_op, high_func):
    """
    Find HTTP methods associated with the route by looking for Methods calls.
    """
    methods = []
    # Search for Methods calls that use the same route object
    route_varnode = call_op.getOutput()
    if route_varnode is None:
        # If the CALL doesn't produce an output, use the second input (route object)
        route_varnode = call_op.getInput(1)
    pcode_ops = list(high_func.getPcodeOps())
    try:
        idx = pcode_ops.index(call_op)
    except ValueError:
        debug_print("[DEBUG] addRegexpMatcher call not found in PcodeOps.")
        return methods
    for op in pcode_ops[idx+1:]:
        if op.getOpcode() == PcodeOp.CALL:
            called_func_addr = op.getInput(0).getAddress()
            called_func_name = get_function_name_at(called_func_addr)
            if "Methods" in called_func_name:
                # Check if the route object is the same
                if op.getInput(1).equals(route_varnode):
                    # Extract methods from arguments
                    for i in range(2, op.getNumInputs()):
                        method = get_string_from_varnode(op.getInput(i), high_func)
                        if method and method != "<unknown_string>":
                            methods.append(method)
                    break
    return methods if methods else ["ALL"]

def find_handler_for_route(call_op, high_func):
    """
    Find the handler function associated with the route.
    Implements recursive tracing to resolve the handler function.
    """
    handler = "<unknown_handler>"
    # Search for Handler, HandlerFunc, or newobject calls that use the same route object
    route_varnode = call_op.getOutput()
    if route_varnode is None:
        # If the CALL doesn't produce an output, use the second input (route object)
        route_varnode = call_op.getInput(1)
    pcode_ops = list(high_func.getPcodeOps())
    try:
        idx = pcode_ops.index(call_op)
    except ValueError:
        debug_print("[DEBUG] addRegexpMatcher call not found in PcodeOps.")
        return handler
    for op in pcode_ops[idx+1:]:
        if op.getOpcode() == PcodeOp.CALL:
            called_func_addr = op.getInput(0).getAddress()
            called_func_name = get_function_name_at(called_func_addr)
            if ("HandlerFunc" in called_func_name or
                "Handler" in called_func_name or
                "newobject" in called_func_name):
                # Check if the route object is the same
                if op.getInput(1).equals(route_varnode):
                    # Extract handler function name from the appropriate input
                    # The handler is usually the second or third input
                    handler_varnode = op.getInput(2) if op.getNumInputs() > 2 else None
                    if handler_varnode:
                        handler = resolve_varnode_to_function(handler_varnode, high_func)
                        if handler != "<unknown_handler>":
                            return handler
                        else:
                            debug_print("[DEBUG] Handler could not be resolved for route.")
                            return handler
    return handler

def resolve_varnode_to_function(varnode, high_func, visited=None):
    """
    Recursively resolve a varnode to a function name.
    """
    if visited is None:
        visited = set()
    if varnode in visited:
        debug_print("[DEBUG] Already visited varnode during handler resolution: " + str(varnode))
        return "<unknown_handler>"
    visited.add(varnode)

    if varnode.isAddress():
        addr = varnode.getAddress()
        func = getFunctionAt(addr)
        if func:
            debug_print("[DEBUG] Resolved handler at address {}: {}".format(addr, func.getName()))
            return func.getName()
        else:
            debug_print("[DEBUG] No function found at address: " + str(addr))
    elif varnode.isConstant():
        addr = toAddr(varnode.getOffset())
        func = getFunctionAt(addr)
        if func:
            debug_print("[DEBUG] Resolved handler at constant address {}: {}".format(addr, func.getName()))
            return func.getName()
        else:
            debug_print("[DEBUG] No function found at constant address: " + str(addr))
    else:
        defining_op = varnode.getDef()
        if defining_op:
            opcode = defining_op.getOpcode()
            if opcode == PcodeOp.CALL:
                called_func_addr = defining_op.getInput(0).getAddress()
                func = getFunctionAt(called_func_addr)
                if func:
                    debug_print("[DEBUG] Resolved handler from CALL opcode at address {}: {}".format(called_func_addr, func.getName()))
                    return func.getName()
                else:
                    debug_print("[DEBUG] No function found at called address: " + str(called_func_addr))
            elif opcode == PcodeOp.COPY:
                input_varnode = defining_op.getInput(0)
                return resolve_varnode_to_function(input_varnode, high_func, visited)
            elif opcode == PcodeOp.PTRADD:
                base_varnode = defining_op.getInput(0)
                offset_varnode = defining_op.getInput(1)
                base_address = base_varnode.getAddress()
                if base_address:
                    handler_address = base_address.add(offset_varnode.getOffset())
                    func = getFunctionAt(handler_address)
                    if func:
                        debug_print("[DEBUG] Resolved handler at computed address {}: {}".format(handler_address, func.getName()))
                        return func.getName()
                    else:
                        debug_print("[DEBUG] No function found at computed handler address: " + str(handler_address))
            elif opcode == PcodeOp.SUBPIECE:
                input_varnode = defining_op.getInput(0)
                return resolve_varnode_to_function(input_varnode, high_func, visited)
            else:
                try:
                    opcode_name = PcodeOp.getMnemonic(opcode)
                except Exception as e:
                    opcode_name = "<unknown_opcode>"
                debug_print("[DEBUG] Unhandled opcode in handler resolution: " + opcode_name)
        else:
            debug_print("[DEBUG] No defining operation for varnode: " + str(varnode))
    return "<unknown_handler>"

def get_function_name_at(address):
    """
    Get the function name at a given address.
    """
    func = getFunctionAt(address)
    if func:
        return func.getName()
    else:
        symbol = getSymbolAt(address)
        if symbol:
            return symbol.getName()
    return "<unknown_function>"

def main():
    # Print header for output with fixed-width formatting
    header = "{:<60} {:<20} {:<40} {:<60}".format("Path", "Method", "Handler", "Defined In")
    print(header)
    print("-" * len(header))

    # Step 1: Find RegisterRoutes functions
    register_routes_funcs = find_register_routes_functions()

    # Step 2: Find other functions calling addRegexpMatcher
    other_funcs = find_functions_calling_addRegexpMatcher()

    # Combine both sets of functions
    all_target_funcs = register_routes_funcs + other_funcs

    if not all_target_funcs:
        print("[ERROR] No functions found that register routes.")
        return

    # Step 3: Analyze all target functions
    all_routes = analyze_register_routes_functions(register_routes_funcs)  # Prioritize RegisterRoutes functions
    additional_routes = analyze_functions(other_funcs)  # Analyze other functions

    all_routes.extend(additional_routes)

    if not all_routes:
        print("\n[INFO] No routes extracted.")
    else:
        # After extraction, print all routes in formatted columns
        for route in all_routes:
            path = route['path']
            methods = ", ".join(route['methods']) if route['methods'] else "ALL"
            handler = route['handler']
            defined_in = route['defined_in']
            row = "{:<60} {:<20} {:<40} {:<60}".format(path, methods, handler, defined_in)
            print(row)

if __name__ == "__main__":
    main()
