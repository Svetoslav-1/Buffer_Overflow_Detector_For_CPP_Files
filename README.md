# C++ Buffer Overflow Detector

A static analysis tool for detecting potential buffer overflow vulnerabilities in C++ source code.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This tool scans C++ source files to identify patterns and code constructs that could lead to buffer overflow vulnerabilities. Buffer overflows are one of the most common and dangerous security vulnerabilities, potentially allowing attackers to execute arbitrary code on vulnerable systems.

The detector uses pattern matching and static analysis techniques to flag risky code patterns such as:

- Usage of unsafe C string functions (e.g., `strcpy`, `gets`, `strcat`)
- Fixed-size buffer declarations that might be overflowed
- Potentially unsafe memory operations (e.g., unchecked `memcpy` calls)
- Array access without proper bounds checking
- Loop boundary issues that might lead to buffer overruns
- Functions with pointer parameters lacking proper safeguards

## Installation

### Prerequisites

- C++ compiler (g++ or compatible)
- C++11 support or higher

### Building the Detector

Clone this repository and build the detector:


git clone https://github.com/yourusername/cpp-buffer-overflow-detector.git
cd cpp-buffer-overflow-detector
g++ -o detector Detector.cpp -std=c++11
Usage
Run the detector against a C++ source file:
bash./detector <Path_to_File.cpp>
Example:
bash./detector vulnerable.cpp
Sample Output
Detected 8 potential buffer overflow vulnerabilities in vulnerable.cpp:
---------------------------------------------------------------------
Line 7: [High] strcpy - Unsafe C string function in context: dest, src) {
    // Vulnerable: no bounds checking
    strcpy(dest, src);
}
Line 14: [Medium] for loop - Loop may have improper boundary checking for array access
Line 24: [Medium] Array access - Unchecked array access with variable: size
Line 31: [Medium] memcpy - Potential unsafe memcpy in context: memcpy(dest, src, srcLen);
Line 38: [High] gets - Unsafe C string function in context: std::cout << "Enter your name: ";
    gets(buffer);  // Never use gets()
Line 45: [Medium] sprintf - Unsafe C string function in context: sprintf(buffer, "User: %s (ID: %d)", username, userID);
...
---------------------------------------------------------------------
Note: This is a static analysis and may produce false positives.
Each finding should be manually verified.
Included Test File
This repository includes a sample vulnerable C++ file (vulnerable.cpp) with multiple buffer overflow vulnerabilities to help test the detector's capabilities.
The file contains examples of:

Unsafe string function calls
Off-by-one errors
Unchecked memory operations
Dynamic buffer mismanagement
Incorrect loop boundaries
Standard library misuse

How It Works
The detector implements several types of analysis:

Pattern Matching: Uses regular expressions to identify potentially unsafe functions and constructs
Loop Analysis: Examines loop conditions that might lead to array overruns
Function Analysis: Analyzes functions that take buffers as parameters
Array Access Analysis: Detects unchecked array indexing

Each finding is assigned a severity level (Low, Medium, High) based on the potential risk and likelihood of exploitation.
Limitations

The detector uses static analysis and pattern matching, which can lead to false positives
Some complex vulnerabilities requiring data flow analysis might be missed
Macro expansions and template instantiations are not fully analyzed
The tool doesn't perform deep context-sensitive analysis
External libraries and header-only code are not analyzed unless included in the scanned file

Future Improvements

Support for analyzing multiple files and their interactions
Data flow analysis for more accurate vulnerability detection
Detection of use-after-free and double-free vulnerabilities
Integration with build systems
Support for additional languages beyond C++
AI-powered pattern recognition for identifying novel vulnerability patterns
Remediation suggestions for each vulnerability type
Interactive mode with code visualization
Integration with CI/CD pipelines

Common Buffer Overflow Vulnerabilities
The detector specifically looks for these high-risk patterns:
1. Unsafe C String Functions
Functions like strcpy(), strcat(), gets(), and sprintf() lack built-in bounds checking:
cppchar buffer[10];
strcpy(buffer, "This string is way too long and will overflow the buffer");
2. Off-By-One Errors
Common loop errors that write one byte past the end of a buffer:
cppchar buffer[10];
for (int i = 0; i <= 10; i++) { // Should be < 10
    buffer[i] = 'A';
}
3. Unchecked Memory Operations
Using memcpy() or similar functions without size validation:
cppchar dest[10];
char* source = getLargeDataFromSomewhere();
memcpy(dest, source, getLargeSize()); // No check if dest can hold the data
4. Unchecked Array Indexing
Using variables as array indices without bounds checking:
cppint array[10];
int index = getUserInput();
array[index] = 42; // No check if index is within array bounds
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments

Inspired by secure coding practices from CERT C++ Coding Standard
References MITRE's Common Weakness Enumeration (CWE) for buffer overflow vulnerabilities
