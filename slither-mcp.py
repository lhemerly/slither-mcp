# /// script
# requires-python = ">=3.12"
# dependencies = [
#    "mcp[cli]>=1.6.0",
#    "slither-analyzer>=0.11.0",]
# ///

from mcp.server.fastmcp import FastMCP
from slither.slither import Slither
from slither.analyses.data_dependency.data_dependency import is_dependent
from slither.detectors import all_detectors

# Initialize the MCP server
mcp = FastMCP("SlitherMCP", dependencies=[])

@mcp.tool()
def slither_analyze(contract_path: str) -> str:
    """
    Perform a complete Slither analysis on a Solidity contract or project.
    
    Args:
        contract_path (str): Path to a Solidity file or directory containing Solidity files.
        
    Returns:
        str: A comprehensive security analysis report with all detected vulnerabilities.
        
    This tool is equivalent to running 'slither .' on the command line, providing a full
    security analysis of the smart contract(s). It detects common vulnerabilities like
    reentrancy, unchecked return values, uninitialized variables, and many more issues.
    """
    slither = Slither(contract_path)
    results = []
    
    # Run all detectors
    all_detector_classes = [d for d in all_detectors]
    for detector_cls in all_detector_classes:
        detector = detector_cls(slither)
        issues = detector.detect()
        
        if issues:
            results.append(f"\n== {detector.ARGUMENT} : {detector.HELP} ==")
            for issue in issues:
                results.append(f"- {issue.description}")
    
    # Add basic stats
    results.insert(0, f"Analysis of {contract_path}:")
    results.insert(1, f"Found {len(slither.contracts)} contracts")
    
    if not results[2:]:  # If no detector results
        results.append("No vulnerabilities found!")
        
    return "\n".join(results)

@mcp.tool()
def slither_check_upgradeability(contract_name: str, proxy_name: str = None, new_contract_name: str = None) -> str:
    """
    Perform upgradeability checks on a contract using Slither.

    Args:
        contract_name (str): The name of the contract to check.
        proxy_name (str, optional): The name of the proxy contract, if applicable.
        new_contract_name (str, optional): The name of the new contract for comparison.

    Returns:
        str: A summary of the upgradeability issues detected.
    """
    slither = Slither(contract_name)
    issues = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            # Check storage layout
            storage_layout = []
            for var in contract.state_variables_ordered:
                storage_layout.append(f"{var.name}: {var.type}")
            issues.append(f"Storage layout: {', '.join(storage_layout)}")

            # Check for initializers
            init_functions = [f for f in contract.functions if f.name == "initialize"]
            if not init_functions:
                issues.append("Warning: No initializer function found")

            # Check for immutable variables
            immutables = [var.name for var in contract.state_variables if var.is_constant]
            if immutables:
                issues.append(f"Immutable variables: {', '.join(immutables)}")

            if proxy_name:
                proxy = slither.get_contract_from_name(proxy_name)
                if proxy:
                    # Check delegate calls
                    delegatecalls = []
                    for function in proxy.functions:
                        for node in function.nodes:
                            if node.contains_delegate_call():
                                delegatecalls.append(function.name)
                    if delegatecalls:
                        issues.append(f"Proxy delegate calls in: {', '.join(delegatecalls)}")

    return "\n".join(issues) if issues else f"No upgradeability issues detected for {contract_name}."

@mcp.tool()
def slither_check_erc(contract_name: str, erc_standard: str) -> str:
    """
    Check ERC conformance of a contract using Slither.

    Args:
        contract_name (str): The name of the contract to check.
        erc_standard (str): The ERC standard to validate against (e.g., ERC20, ERC721).
    """
    slither = Slither(contract_name)
    results = []

    erc_functions = {
        'ERC20': {
            'required': ['totalSupply', 'balanceOf', 'transfer', 'transferFrom', 'approve', 'allowance'],
            'events': ['Transfer', 'Approval']
        },
        'ERC721': {
            'required': ['balanceOf', 'ownerOf', 'transferFrom', 'approve', 'getApproved', 'setApprovalForAll', 'isApprovedForAll'],
            'events': ['Transfer', 'Approval', 'ApprovalForAll']
        }
    }

    for contract in slither.contracts:
        if contract.name == contract_name:
            if erc_standard in erc_functions:
                # Check required functions
                function_names = {f.name for f in contract.functions}
                required = erc_functions[erc_standard]['required']
                missing = [f for f in required if f not in function_names]
                if missing:
                    results.append(f"Missing required functions: {', '.join(missing)}")
                
                # Check events
                event_names = {e.name for e in contract.events}
                required_events = erc_functions[erc_standard]['events']
                missing_events = [e for e in required_events if e not in event_names]
                if missing_events:
                    results.append(f"Missing required events: {', '.join(missing_events)}")

    return "\n".join(results) if results else f"Contract {contract_name} appears to be {erc_standard} compliant."

@mcp.tool()
def slither_find_paths(contract_name: str, target_function: str) -> str:
    """
    Find all paths that reach a given target function in a contract using Slither.
    """
    slither = Slither(contract_name)
    paths = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            target = contract.get_function_from_signature(target_function)
            if target:
                for function in contract.functions:
                    if target in function.all_internal_calls():
                        path = []
                        current = function
                        while current:
                            path.append(current.name)
                            # For simplicity, we'll just take the first caller
                            callers = [f for f in contract.functions if current in f.all_internal_calls()]
                            current = callers[0] if callers else None
                        paths.append(" -> ".join(reversed(path)))

    return "\n".join(paths) if paths else f"No paths to {target_function} found in {contract_name}."

@mcp.tool()
def slither_analyze_dependencies(contract_name: str, variable_name: str) -> str:
    """
    Analyze data dependencies for a specific variable in a contract.

    Args:
        contract_name (str): The name of the contract to analyze.
        variable_name (str): The name of the variable to check dependencies for.

    Returns:
        str: A summary of the data dependencies found.
    """
    slither = Slither(contract_name)
    results = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            var = contract.get_state_variable_from_name(variable_name)
            if var:
                # Find functions that read or write to this variable
                for function in contract.functions:
                    if var in function.state_variables_read:
                        results.append(f"Function {function.name} reads {variable_name}")
                    if var in function.state_variables_written:
                        results.append(f"Function {function.name} writes to {variable_name}")
                    
                    # Check for dependencies between variables
                    for other_var in contract.state_variables:
                        if other_var != var and is_dependent(var, other_var, contract):
                            results.append(f"{variable_name} depends on {other_var.name}")

    return "\n".join(results) if results else f"No dependencies found for {variable_name} in {contract_name}."

@mcp.tool()
def slither_generate_ir(contract_name: str, function_name: str) -> str:
    """
    Generate Slither's intermediate representation (IR) for a specific function.

    Args:
        contract_name (str): The name of the contract to analyze.
        function_name (str): The name of the function to generate IR for.

    Returns:
        str: The IR representation of the function.
    """
    slither = Slither(contract_name)
    ir_lines = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            function = contract.get_function_from_signature(function_name)
            if function:
                ir_lines.append(f"IR for {function_name}:")
                for node in function.nodes:
                    ir_lines.append(f"Node type: {node.type}")
                    if node.expression:
                        ir_lines.append(f"Expression: {node.expression}")
                    if node.irs:
                        for ir in node.irs:
                            ir_lines.append(f"IR: {ir}")
                    ir_lines.append("---")

    return "\n".join(ir_lines) if ir_lines else f"No IR generated for {function_name} in {contract_name}."

@mcp.tool()
def slither_print_summary(contract_name: str) -> str:
    """
    Print a detailed summary of a contract using Slither.
    """
    slither = Slither(contract_name)
    summary = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            # Basic contract info
            summary.append(f"Contract: {contract.name}")
            summary.append(f"Inheritance: {[c.name for c in contract.inheritance]}")
            
            # Functions
            summary.append("\nFunctions:")
            for function in contract.functions:
                visibility = "public" if function.visibility in ["public", "external"] else "internal/private"
                state_mutability = "view/pure" if function.view or function.pure else "state-changing"
                summary.append(f"- {function.name}: {visibility}, {state_mutability}")
                summary.append(f"  Reads: {[v.name for v in function.state_variables_read]}")
                summary.append(f"  Writes: {[v.name for v in function.state_variables_written]}")

            # State variables
            summary.append("\nState Variables:")
            for var in contract.state_variables:
                mutability = "constant" if var.is_constant else "immutable" if var.is_immutable else "mutable"
                summary.append(f"- {var.name}: {var.type}, {mutability}")

            # Events
            summary.append("\nEvents:")
            for event in contract.events:
                summary.append(f"- {event.name}")

    return "\n".join(summary) if summary else f"No summary available for {contract_name}."

@mcp.tool()
def slither_flatten_contract(contract_name: str, strategy: str = "MostDerived") -> str:
    """
    Flatten a contract's codebase using Slither.
    """
    slither = Slither(contract_name)
    flattened = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            # Header
            flattened.append(f"// Flattened version of {contract_name}")
            flattened.append(f"// Strategy: {strategy}\n")

            # Collect all dependencies
            deps = set()
            for base in contract.inheritance:
                deps.update(base.file_scope.imports)
            
            # Add SPDX and pragma
            flattened.append("// SPDX-License-Identifier: MIT")
            flattened.append(contract.file_scope.pragma_directives[0].source_mapping.content.decode() if contract.file_scope.pragma_directives else "")
            
            # Add imports (if using LocalImport strategy)
            if strategy == "LocalImport":
                for dep in deps:
                    flattened.append(f"import {dep};")

            # Add all inherited contracts
            for base in reversed(contract.inheritance):
                flattened.append(f"\n// From {base.file_scope.filename}:")
                flattened.append(base.source_mapping.content.decode())

            # Add the main contract
            flattened.append(f"\n// Main contract {contract_name}:")
            flattened.append(contract.source_mapping.content.decode())

    return "\n".join(flattened) if flattened else f"Could not flatten {contract_name}."

@mcp.tool()
def slither_check_properties(contract_name: str) -> str:
    """
    Check various security properties of a contract using Slither.

    Args:
        contract_name (str): The name of the contract to check.

    Returns:
        str: A summary of the security properties checked.
    """
    slither = Slither(contract_name)
    properties = []

    for contract in slither.contracts:
        if contract.name == contract_name:
            # Check for reentrancy
            for function in contract.functions:
                for node in function.nodes:
                    if node.can_reenter():
                        properties.append(f"Potential reentrancy in {function.name}")

            # Check for state variable shadowing
            for var in contract.state_variables:
                for inherited in contract.inheritance:
                    if inherited.get_state_variable_from_name(var.name):
                        properties.append(f"State variable shadowing: {var.name}")

            # Check for tx.origin usage
            for function in contract.functions:
                if any("tx.origin" in str(node.expression) for node in function.nodes if node.expression):
                    properties.append(f"tx.origin used in {function.name}")

            # Check for proper visibility
            for function in contract.functions:
                if function.visibility in ["public", "external"]:
                    if any(var in function.state_variables_written for var in contract.state_variables):
                        properties.append(f"Public function {function.name} modifies state")

            # Check for uninitialized state variables
            for var in contract.state_variables:
                if not var.expression and not var.is_constant:
                    properties.append(f"Uninitialized state variable: {var.name}")

    return "\n".join(properties) if properties else f"No concerning properties found in {contract_name}."

if __name__ == "__main__":
    mcp.run()


