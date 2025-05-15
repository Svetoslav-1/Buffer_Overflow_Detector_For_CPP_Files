#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

class BufferOverflowDetector {
private:
    struct VulnerabilityInfo {
        std::string function;
        int lineNumber;
        std::string description;
        std::string severity;
    };

    std::vector<VulnerabilityInfo> vulnerabilities;
    std::string fileName;

    //patterns for risky functions that might cause buffer overflow
    const std::vector<std::pair<std::regex, std::string>> vulnerablePatterns = {
        {std::regex("\\b(strcpy|strcat|sprintf|gets|scanf)\\s*\\("), "Unsafe C string function"},
        {std::regex("\\bchar\\s+[a-zA-Z0-9_]+\\s*\\[[0-9]+\\]"), "Fixed-size buffer declaration"},
        {std::regex("\\bmemcpy\\s*\\([^,]+,[^,]+,[^)]+\\)"), "Potential unsafe memcpy"},
        {std::regex("\\bnew\\s+char\\s*\\[[^\\]]+\\]"), "Dynamic array allocation"},
        {std::regex("\\bstd::copy\\s*\\("), "std::copy without bounds checking"},
        {std::regex("for\\s*\\([^;]*;[^;]*;[^\\)]*\\)\\s*\\{[^\\}]*\\[[^\\]]*\\]"), "Loop with array access"}
    };

    //more patterns to check for array problems
    const std::vector<std::pair<std::regex, std::string>> arrayAccessPatterns = {
        {std::regex("\\[([^\\]]+)\\]"), "Array access without bounds checking"}
    };

public:
    BufferOverflowDetector(const std::string& file) : fileName(file) {}

    bool analyze() {
        std::ifstream inputFile(fileName);
        if (!inputFile.is_open()) {
            std::cerr << "Error: Could not open file " << fileName << std::endl;
            return false;
        }

        std::string line;
        int lineNumber = 0;

        //read file line by line
        while (std::getline(inputFile, line)) {
            lineNumber++;
            checkLineForVulnerabilities(line, lineNumber);
        }

        inputFile.close();
        return true;
    }

    void checkLineForVulnerabilities(const std::string& line, int lineNumber) {
        //check if the line has any dangerous functions
        for (const auto& pattern : vulnerablePatterns) {
            std::smatch matches;
            std::string::const_iterator searchStart(line.cbegin());
            
            while (std::regex_search(searchStart, line.cend(), matches, pattern.first)) {
                std::string functionName = matches[1].matched ? matches[1] : matches[0];
                
                //get some text around the match so we have context
                size_t startPos = matches.position();
                size_t contextStart = (startPos > 20) ? startPos - 20 : 0;
                size_t contextLength = matches.length() + 40;
                if (contextStart + contextLength > line.length()) {
                    contextLength = line.length() - contextStart;
                }
                
                std::string context = line.substr(contextStart, contextLength);
                
                //decide how bad this vulnerability is
                std::string severity = "Medium";
                if (functionName == "strcpy" || functionName == "gets") {
                    severity = "High";
                }
                
                vulnerabilities.push_back({
                    functionName,
                    lineNumber,
                    pattern.second + " in context: " + context,
                    severity
                });
                
                searchStart = matches.suffix().first;
            }
        }

        //look for array indexing that might be dangerous
        for (const auto& pattern : arrayAccessPatterns) {
            std::smatch matches;
            std::string::const_iterator searchStart(line.cbegin());
            
            while (std::regex_search(searchStart, line.cend(), matches, pattern.first)) {
                std::string indexExpr = matches[1];
                
                //if index is just a variable name it might overflow
                if (std::regex_match(indexExpr, std::regex("[a-zA-Z_][a-zA-Z0-9_]*"))) {
                    vulnerabilities.push_back({
                        "Array access",
                        lineNumber,
                        "Unchecked array access with variable: " + indexExpr,
                        "Medium"
                    });
                }
                
                searchStart = matches.suffix().first;
            }
        }
    }

    void detectLoopBoundaries() {
        std::ifstream inputFile(fileName);
        if (!inputFile.is_open()) {
            return;
        }

        //read the entire file at once for loop analysis
        std::string content((std::istreambuf_iterator<char>(inputFile)),
                         std::istreambuf_iterator<char>());
        inputFile.close();

        //find for loops that might access arrays
        std::regex loopRegex("for\\s*\\(([^;]*);([^;]*);([^\\)]*)\\)\\s*\\{([^\\}]*)\\}");
        std::smatch matches;
        std::string::const_iterator searchStart(content.cbegin());
        
        while (std::regex_search(searchStart, content.cend(), matches, loopRegex)) {
            std::string initialization = matches[1];
            std::string condition = matches[2];
            std::string increment = matches[3];
            std::string loopBody = matches[4];
            
            //check if loop uses arrays
            if (std::regex_search(loopBody, std::regex("\\[[^\\]]+\\]"))) {
                //check if loop has proper boundary check like i < size
                bool hasProperBoundCheck = std::regex_search(condition, std::regex("\\s*[a-zA-Z0-9_]+\\s*<\\s*[a-zA-Z0-9_]+(\\.[a-zA-Z0-9_]+)?(\\.size\\(\\)|\\.length|\\s*-\\s*1)"));
                
                if (!hasProperBoundCheck) {
                    int lineNumber = std::count(content.begin(), matches.position() + content.begin(), '\n') + 1;
                    vulnerabilities.push_back({
                        "Loop boundary",
                        lineNumber,
                        "Loop may have improper boundary checking for array access",
                        "Medium"
                    });
                }
            }
            
            searchStart = matches.suffix().first;
        }
    }

    void printResults() {
        if (vulnerabilities.empty()) {
            std::cout << "No potential buffer overflow vulnerabilities detected." << std::endl;
            return;
        }

        //show summary of all issues found
        std::cout << "Detected " << vulnerabilities.size() << " potential buffer overflow vulnerabilities in " << fileName << ":" << std::endl;
        std::cout << "---------------------------------------------------------------------" << std::endl;
        
        for (const auto& vuln : vulnerabilities) {
            std::cout << "Line " << vuln.lineNumber << ": [" << vuln.severity << "] " 
                     << vuln.function << " - " << vuln.description << std::endl;
        }
        
        std::cout << "---------------------------------------------------------------------" << std::endl;
        std::cout << "Note: This is a static analysis and may produce false positives." << std::endl;
        std::cout << "Each finding should be manually verified." << std::endl;
    }

    void analyzeFunctionCalls() {
        std::ifstream inputFile(fileName);
        if (!inputFile.is_open()) {
            return;
        }

        //load file for function analysis
        std::string content((std::istreambuf_iterator<char>(inputFile)),
                         std::istreambuf_iterator<char>());
        inputFile.close();

        //find functions that might handle buffers
        std::regex funcRegex("\\b(void|int|char|bool|std::string|auto)\\s+([a-zA-Z0-9_]+)\\s*\\(([^\\)]*)\\)\\s*\\{");
        std::smatch matches;
        std::string::const_iterator searchStart(content.cbegin());
        
        while (std::regex_search(searchStart, content.cend(), matches, funcRegex)) {
            std::string returnType = matches[1];
            std::string funcName = matches[2];
            std::string params = matches[3];
            
            //check if function takes pointers or arrays
            if (std::regex_search(params, std::regex("(char|int|float|double)\\s*\\*\\s*[a-zA-Z0-9_]+"))) {
                int lineNumber = std::count(content.begin(), matches.position() + content.begin(), '\n') + 1;
                
                //look inside function body
                size_t funcStartPos = matches.position() + matches.length() - 1; //position of opening brace
                size_t funcEndPos = content.find_first_of('}', funcStartPos);
                if (funcEndPos != std::string::npos) {
                    std::string funcBody = content.substr(funcStartPos, funcEndPos - funcStartPos);
                    
                    //check if buffer is written to without checking size
                    if (std::regex_search(funcBody, std::regex("=\\s*[^;]*;"))) {
                        vulnerabilities.push_back({
                            funcName,
                            lineNumber,
                            "Function with pointer/array parameters may have unchecked writes",
                            "Medium"
                        });
                    }
                }
            }
            
            searchStart = matches.suffix().first;
        }
    }

    void runFullAnalysis() {
        //run all the checks one by one
        if (!analyze()) {
            return;
        }
        detectLoopBoundaries();
        analyzeFunctionCalls();
        printResults();
    }
};

int main(int argc, char* argv[]) {
    //check if user provided a filename
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <cpp_file>" << std::endl;
        return 1;
    }

    std::string fileName = argv[1];
    BufferOverflowDetector detector(fileName);
    detector.runFullAnalysis();
    
    return 0;
}
