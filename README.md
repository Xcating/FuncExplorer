# FuncExplorer README

## [中文版本](README_zh-cn.md)

### **FuncExplorer**

FuncExplorer is a Python-based GUI application built with PyQt5 that allows users to search and explore function definitions and related information. It categorizes functions into important functions, virtual functions, and ordinary functions, providing a user-friendly interface with syntax highlighting for better readability.

### **Features**

- **Clean Input Processing**: Removes unnecessary prefixes and characters from user input.
- **Offset Parsing**: Handles hexadecimal offsets and converts them for processing.
- **Function Categorization**: Classifies functions into important, virtual, and ordinary categories.
- **Syntax Highlighting**: Enhances the readability of function definitions with color-coded syntax.
- **User-Friendly GUI**: Intuitive interface with search functionality and categorized display of results.
- **Error Handling**: Provides informative error messages and logs errors for debugging.

### **Installation**

#### **Prerequisites**

- **Python 3.6 or higher**
- **PyQt5**

#### **Steps**

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/FuncExplorer.git
   cd FuncExplorer
   ```

2. **Create a Virtual Environment (Optional but Recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Required Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   *If `requirements.txt` is not provided, install PyQt5 directly:*

   ```bash
   pip install PyQt5
   ```

4. **Prepare Data Files**

   Ensure that `functions.txt` and `important_functions.txt` are placed in the same directory as the `FuncExplorer` script. These files should contain the necessary function information in the expected format.

### **Usage**

1. **Run the Application**

   ```bash
   python FuncExplorer.py
   ```

2. **Using the GUI**

   - **Input Field**: Enter the function name or function address you wish to search.
   - **Search Button**: Click to perform the search.
   - **Results Area**: View categorized function information with syntax highlighting.

### **File Structure**

- `FuncExplorer.py`: Main application script containing the GUI and functionality.
- `functions.txt`: Text file containing function definitions and related information.
- `important_functions.txt`: Text file listing important function addresses.
- `requirements.txt`: (Optional) Lists Python dependencies.

### **Logging**

Errors and important events are logged using Python’s `logging` module. Logs are configured to capture error-level messages, which can be helpful for debugging purposes.

### **Contributing**

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

### **License**

This project adopts GPLv3 license. Please refer to the [LICENSE](LICENSE) document for details.