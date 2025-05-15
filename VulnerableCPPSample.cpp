#include <iostream>
#include <cstring>
#include <vector>

//function that copies strings without checking size
void copyUserData(char* dest, const char* src) {
    //vulnerable: no bounds checking
    strcpy(dest, src);
}

//function with bad array accessing
void processArray(int arr[], int size) {
    int i;
    //vulnerable: loop bound uses <= instead of <
    for (i = 0; i <= size; i++) {
        arr[i] = i * 2;
    }
}

//function that might write past the end
void fillBuffer(char* buffer, int size) {
    //vulnerable: writes size+1 bytes (including null terminator)
    for (int i = 0; i < size; i++) {
        buffer[i] = 'A';
    }
    buffer[size] = '\0'; //this is one byte past the allocated memory
}

//function that might copy too much data
void copyData(char* dest, const char* src, int srcLen) {
    //vulnerable: no check that dest can hold srcLen bytes
    memcpy(dest, src, srcLen);
}

//function using gets which is super dangerous
void readUserInput(char* buffer) {
    //vulnerable: gets() has no bounds checking
    std::cout << "Enter your name: ";
    gets(buffer);  //never use gets() in real code!
}

//function with sprintf that could overflow
void formatOutput(char* buffer, const char* username, int userID) {
    //vulnerable: sprintf can overflow if username is too long
    sprintf(buffer, "User: %s (ID: %d)", username, userID);
}

//function that allocates memory but doesn't manage it well
char* createGreeting(const char* name) {
    //this function allocates memory for a greeting,
    //but has several potential issues
    
    //vulnerable: no check for name length
    char* greeting = new char[20];
    
    //vulnerable: could overflow if name > 10 chars
    sprintf(greeting, "Hello, %s!", name);
    
    return greeting;
    //note: also has a memory leak if not deleted by caller
}

//function that misuses std::copy
void copyVector(std::vector<int>& source) {
    int dest[10];
    
    //vulnerable: no check if source.size() > 10
    std::copy(source.begin(), source.end(), dest);
    
    //use the copied data
    for (int i = 0; i < 10; i++) {
        std::cout << dest[i] << " ";
    }
    std::cout << std::endl;
}

//function that doesn't check array bounds
void processUserData(const std::vector<int>& data, int index) {
    int localBuffer[5] = {0};
    
    //vulnerable: no bounds checking on index
    localBuffer[index] = 100;
    
    for (int i = 0; i < 5; i++) {
        std::cout << localBuffer[i] << " ";
    }
}

int main() {
    //example 1: fixed buffer overflow
    char smallBuffer[10];
    const char* longString = "This string is definitely longer than 10 characters";
    copyUserData(smallBuffer, longString); //will overflow
    
    //example 2: array bounds violation
    int numbers[5] = {1, 2, 3, 4, 5};
    processArray(numbers, 5); //will write to numbers[5], which is out of bounds
    
    //example 3: off-by-one error
    char nameBuffer[10];
    fillBuffer(nameBuffer, 10); //will write to nameBuffer[10], which is out of bounds
    
    //example 4: static buffer with user input
    char userInput[20];
    readUserInput(userInput); //vulnerable to overflow if input > 19 chars
    
    //example 5: sprintf overflow
    char outputBuffer[20];
    formatOutput(outputBuffer, "John_With_A_Very_Long_Surname", 12345); //will overflow
    
    //example 6: dynamic allocation with overflow
    char* greeting = createGreeting("Bob_With_A_Very_Long_Name");
    std::cout << greeting << std::endl;
    delete[] greeting; //clean up, at least
    
    //example 7: std::copy overflow
    std::vector<int> largeVector(15, 42); //vector with 15 elements
    copyVector(largeVector); //will overflow the dest[10] array
    
    //example 8: out of bounds array access
    std::vector<int> userData = {1, 2, 3};
    processUserData(userData, 10); //will access localBuffer[10], which is out of bounds
    
    return 0;
}
