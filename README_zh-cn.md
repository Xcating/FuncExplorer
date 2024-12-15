# FuncExplorer README

## [English Version](README.md)

### **FuncExplorer**

FuncExplorer 是一个基于 Python 和 PyQt5 构建的图形用户界面（GUI）应用程序，允许用户搜索和浏览函数定义及相关信息。它将函数分类为重点函数、虚函数和普通函数，并提供了具有语法高亮的用户友好界面，以提高可读性。

### **功能特性**

- **输入清理**：移除用户输入中的不必要前缀和字符。
- **偏移量解析**：处理十六进制偏移量并进行转换处理。
- **函数分类**：将函数分类为重点函数、虚函数和普通函数。
- **语法高亮**：通过颜色编码增强函数定义的可读性。
- **用户友好的GUI**：直观的界面，具有搜索功能和分类显示结果。
- **错误处理**：提供信息丰富的错误消息并记录错误以便调试。

### **安装指南**

#### **前提条件**

- **Python 3.6 或更高版本**
- **PyQt5**

#### **安装步骤**

1. **克隆仓库**

   ```bash
   git clone https://github.com/yourusername/FuncExplorer.git
   cd FuncExplorer
   ```

2. **创建虚拟环境（可选，推荐）**

   ```bash
   python -m venv venv
   source venv/bin/activate  # 在Windows上: venv\Scripts\activate
   ```

3. **安装所需依赖**

   ```bash
   pip install -r requirements.txt
   ```

   *如果没有提供 `requirements.txt`，可以直接安装 PyQt5:*

   ```bash
   pip install PyQt5
   ```

4. **准备数据文件**

   确保 `functions.txt` 和 `important_functions.txt` 文件位于 `FuncExplorer` 脚本的同一目录下。这些文件应按照预期格式包含必要的函数信息。

### **使用方法**

1. **运行应用程序**

   ```bash
   python FuncExplorer.py
   ```

2. **使用GUI界面**

   - **输入框**：输入您要搜索的函数名或函数地址。
   - **搜索按钮**：点击以执行搜索。
   - **结果区域**：查看分类后的函数信息，并带有语法高亮显示。

### **文件结构**

- `FuncExplorer.py`: 包含GUI和功能的主应用脚本。
- `functions.txt`: 包含函数定义和相关信息的文本文件。
- `important_functions.txt`: 列出重点函数地址的文本文件。
- `requirements.txt`: （可选）列出Python依赖项。

### **日志记录**

使用 Python 的 `logging` 模块记录错误和重要事件。日志配置为捕获错误级别的信息，有助于调试。

### **贡献**

欢迎贡献！请先分叉（fork）仓库，然后提交拉取请求（pull request）以进行您的改进。

### **许可证**

本项目不采用许可证。