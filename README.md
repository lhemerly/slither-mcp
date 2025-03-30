# Slither MCP Server

This repository contains a Model Context Protocol (MCP) server implementation for Slither, a static analysis framework for Solidity smart contracts. The server provides a set of tools to analyze, validate, and inspect Solidity contracts programmatically.

## Features

- **Comprehensive Security Analysis**: Perform a full security analysis of Solidity contracts, detecting vulnerabilities such as reentrancy, unchecked return values, and uninitialized variables.
- **Upgradeability Checks**: Validate the upgradeability of contracts, including storage layout and proxy delegate calls.
- **ERC Conformance**: Check if a contract adheres to ERC standards like ERC20 and ERC721.
- **Path Finding**: Identify all paths leading to a specific function in a contract.
- **Data Dependency Analysis**: Analyze dependencies for specific variables in a contract.
- **Intermediate Representation (IR)**: Generate Slither's IR for specific functions.
- **Contract Summaries**: Print detailed summaries of contracts, including functions, state variables, and events.
- **Code Flattening**: Flatten a contract's codebase for easier inspection.
- **Security Property Checks**: Validate various security properties, such as reentrancy and state variable shadowing.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/slither-mcp.git
   cd slither-mcp
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the MCP server:
   ```bash
   python server.py
   ```

## Using with Vs Code, Cursor, Claude, etc

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/slither-mcp.git
   cd slither-mcp
   ```

2. Include the following in the MCP server configuration of the corresponding app:
   ```json
      "slitherMCP": {
         "command": "uv",
         "args": [
            "run",
            "path/to/slither-mcp.py"
         ],
         "env": {}
      }
   ```

## Usage

The MCP server exposes the following tools:

### 1. `slither_analyze`
Perform a complete security analysis of a Solidity contract or project.

**Arguments:**
- `contract_path` (str): Path to a Solidity file or directory.

**Returns:**
- A comprehensive security analysis report.

### 2. `slither_check_upgradeability`
Check the upgradeability of a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `proxy_name` (str, optional): Name of the proxy contract.
- `new_contract_name` (str, optional): Name of the new contract for comparison.

**Returns:**
- A summary of upgradeability issues.

### 3. `slither_check_erc`
Validate ERC conformance of a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `erc_standard` (str): ERC standard to validate against (e.g., ERC20, ERC721).

**Returns:**
- A summary of missing functions or events.

### 4. `slither_find_paths`
Find all paths leading to a specific function in a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `target_function` (str): Target function signature.

**Returns:**
- A list of paths to the target function.

### 5. `slither_analyze_dependencies`
Analyze data dependencies for a specific variable in a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `variable_name` (str): Name of the variable.

**Returns:**
- A summary of data dependencies.

### 6. `slither_generate_ir`
Generate Slither's intermediate representation (IR) for a specific function.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `function_name` (str): Name of the function.

**Returns:**
- The IR representation of the function.

### 7. `slither_print_summary`
Print a detailed summary of a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.

**Returns:**
- A detailed summary of the contract.

### 8. `slither_flatten_contract`
Flatten a contract's codebase.

**Arguments:**
- `contract_name` (str): Name of the contract.
- `strategy` (str, optional): Flattening strategy (default: "MostDerived").

**Returns:**
- The flattened contract code.

### 9. `slither_check_properties`
Check various security properties of a contract.

**Arguments:**
- `contract_name` (str): Name of the contract.

**Returns:**
- A summary of security properties checked.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.