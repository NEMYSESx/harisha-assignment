Shamir's Secret Sharing Solver
A robust Go implementation that reconstructs secrets from Shamir's Secret Sharing scheme using Lagrange interpolation with exact arithmetic.
Features

✅ Exact Arithmetic: Uses rational arithmetic for precision with very large numbers
✅ Multiple Base Support: Handles values in bases 2-36
✅ Edge Case Handling: Comprehensive validation and error handling
✅ Clean Output: Returns only the secret number
✅ File Input: Reads JSON test cases from files

Requirements

Go 1.16 or higher
No external dependencies (uses only Go standard library)

Installation

Clone or download the main.go file
Ensure Go is installed on your system

Usage
go run main.go <json_file_path>
Example
go run main.go testcase1.json
