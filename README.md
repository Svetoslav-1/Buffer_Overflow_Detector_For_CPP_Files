# 🛡️ C++ Buffer Overflow Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/C++-11+-blue.svg)](https://isocpp.org/)
[![Static Analysis](https://img.shields.io/badge/Static%20Analysis-Pattern%20Matching-green.svg)](https://en.wikipedia.org/wiki/Static_program_analysis)

A static analysis tool for detecting potential buffer overflow vulnerabilities in C++ source code.

## 🌟 Overview

This tool scans C++ source files to identify patterns and code constructs that could lead to buffer overflow vulnerabilities. Buffer overflows are one of the most common and dangerous security vulnerabilities, potentially allowing attackers to execute arbitrary code on vulnerable systems.

## ✨ Features

- 🔍 Detection of unsafe C string functions (`strcpy`, `gets`, `strcat`, etc.)
- 🧮 Analysis of array bounds and indexing issues
- 🔄 Identification of loop boundary problems that might cause overflows
- 💾 Detection of potentially unsafe memory operations
- 📝 Detailed output with line numbers and severity ratings
- 🔬 Context-aware vulnerability reporting

## 🚀 Installation

### Prerequisites
- C++ compiler (g++ or compatible)
- C++11 support or higher

### Setup
1. Clone the repository:
```bash
git clone https://github.com/Svetoslav-1/cpp-buffer-overflow-detector.git
cd cpp-buffer-overflow-detector
```

2. Build the detector:
```bash
g++ -o detector Detector.cpp -std=c++11
```

## 📋 Usage

To analyze a C++ source file for buffer overflow vulnerabilities:

```bash
./detector <Path_to_File.cpp>
```

Example:

```bash
./detector VulnerableCPPSample.cpp
```

### Sample Output

```
Detected 8 potential buffer overflow vulnerabilities in VulnerableCPPSample.cpp:
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
```

## 📈 Performance

The detector uses pattern matching and static analysis to identify common buffer overflow vulnerabilities, including:

- Unsafe function usage patterns
- Fixed-size buffer declarations
- Loop boundary issues
- Unsafe array indexing
- Pointer arithmetic risks

## 📁 Project Structure

```
cpp-buffer-overflow-detector/
├── Detector.cpp           # Main detector implementation
├── vulnerable.cpp         # Sample file with buffer overflow vulnerabilities
├── LICENSE                # MIT License
└── README.md              # This file
```

## 🔍 Vulnerability Types Detected

The detector specifically looks for these high-risk patterns:

### 1. Unsafe C String Functions

Functions like `strcpy()`, `strcat()`, `gets()`, and `sprintf()` lack built-in bounds checking:

```cpp
char buffer[10];
strcpy(buffer, "This string is way too long and will overflow the buffer");
```

### 2. Off-By-One Errors

Common loop errors that write one byte past the end of a buffer:

```cpp
char buffer[10];
for (int i = 0; i <= 10; i++) { // Should be < 10
    buffer[i] = 'A';
}
```

### 3. Unchecked Memory Operations

Using `memcpy()` or similar functions without size validation:

```cpp
char dest[10];
char* source = getLargeDataFromSomewhere();
memcpy(dest, source, getLargeSize()); // No check if dest can hold the data
```

### 4. Unchecked Array Indexing

Using variables as array indices without bounds checking:

```cpp
int array[10];
int index = getUserInput();
array[index] = 42; // No check if index is within array bounds
```

## 🚧 Limitations

- The detector uses static analysis and pattern matching, which can lead to false positives
- Some complex vulnerabilities requiring data flow analysis might be missed
- Macro expansions and template instantiations are not fully analyzed
- The tool doesn't perform deep context-sensitive analysis
- External libraries and header-only code are not analyzed unless included in the scanned file

## 🔮 Future Improvements

- 🌐 Support for analyzing multiple files and their interactions
- 🧠 AI-powered pattern recognition for identifying novel vulnerability patterns
- 🔄 Data flow analysis for more accurate vulnerability detection
- 🔎 Detection of use-after-free and double-free vulnerabilities
- 🌍 Support for additional languages beyond C++
- 💡 Remediation suggestions for each vulnerability type
- 👁️ Interactive mode with code visualization
- 🔄 Integration with CI/CD pipelines

## 📜 License

MIT License

Copyright (c) 2025 Svetoslav-1

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🙏 Acknowledgments

- Inspired by secure coding practices from CERT C++ Coding Standard
- References MITRE's Common Weakness Enumeration (CWE) for buffer overflow vulnerabilities
