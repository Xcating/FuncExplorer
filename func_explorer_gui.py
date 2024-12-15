import re
import os
import logging
from pathlib import Path
import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QScrollArea, QGroupBox, QGridLayout, QFrame
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

class FuncExplorer:
    def __init__(self):
        self.info_file = Path(__file__).parent / 'functions.txt'
        self.info4_file = Path(__file__).parent / 'important_functions.txt'
    
    def clean_input(self, input_address):
        """清理输入地址，移除前缀和多余字符"""
        patterns = [
            r'^#', r'^/', r'^查', r'^找', r'^看', r'^函数',
            r'^Function', r'^function', r'^Func', r'^func',
            r'^call', r'^Call', r'^ ', r'^/'
        ]
        for pattern in patterns:
            input_address = re.sub(pattern, '', input_address).strip()
        return input_address
    
    def parse_offsets(self, input_address):
        """解析输入中的偏移量"""
        if '+' in input_address:
            parts = input_address.split('+')
            offsets = []
            for offset in parts[1:]:
                hex_offset = '0x' + re.sub(r'[^0-9A-Fa-f]', '', offset)
                try:
                    dec_offset = int(hex_offset, 16)
                    offsets.append(dec_offset + 0x400000)
                except ValueError:
                    logger.error(f"Invalid offset: {offset}")
            input_address = ','.join([format(offset, 'X') for offset in offsets])
            return input_address
        return input_address
    
    def read_file(self, file_path):
        """读取文件内容并返回行列表"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f]
        except Exception as err:
            logger.error(f"Error reading {file_path}:", exc_info=err)
            return None
    
    def filter_lines(self, input_address, lines):
        """根据输入地址过滤匹配的行"""
        matched_lines = []
        if re.fullmatch(r'^[0-9A-Fa-f]+$', input_address):
            # 处理十六进制地址匹配
            try:
                input_number = int(input_address, 16)
            except ValueError:
                return None
            for line in lines:
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                try:
                    current_number = int(parts[0], 16)
                    if input_number - 0xFFFF <= current_number <= input_number:
                        matched_lines.append(line)
                except ValueError:
                    continue
            return [matched_lines[-1]] if matched_lines else []
        else:
            # 处理模糊匹配
            keywords = [kw.strip() for kw in re.split(r'[\s,;，。]+', input_address) if kw.strip()]
            if keywords:
                regex = re.compile(''.join([f'(?=.*{re.escape(kw)})' for kw in keywords]), re.IGNORECASE)
                matched_lines = [line for line in lines if regex.search(line)][:1000]
                return matched_lines
    
    def categorize_functions(self, matched_lines, important_functions):
        """分类函数信息为重点函数、普通函数和虚函数"""
        message_im = []
        message_vi = []
        message = []
        for line in matched_lines:
            messages = ""
            parts = line.split('\t')
            if len(parts) < 5:
                continue
            # 判断是否为重点函数
            is_important_function = False
            for te_line in important_functions:
                try:
                    a = int(te_line, 16)
                    b = int(parts[0], 16)
                    if a == b:
                        messages += "[此函数是重点函数*]\n"
                        is_important_function = True
                        break
                except ValueError:
                    continue
            # 拼接函数信息
            messages += f"函数头：{parts[0]}\n函数定义：{parts[1]}\n返回与临时寄存器组：{parts[2]}\n"
            parts[3] = parts[3].replace('0x', '').strip()
            if parts[3]:
                messages += f"函数清栈：add esp,{parts[3]} (十六进制)\n"
            messages += f"函数简介：{parts[4]}\n"
            if len(parts) > 6 and parts[6]:
                messages += f"{parts[6]}\n"
            messages = messages.replace(" ;", "\n ")
            # 分类存储
            if is_important_function:
                message_im.append(messages)
            else:
                if len(parts) > 6 and parts[6]:
                    message_vi.append(messages)
                else:
                    message.append(messages)
        return message_im, message_vi, message
    
    def get_function_info(self, input_address):
        """主查询函数，返回分类后的函数信息列表"""
        input_address = self.clean_input(input_address)
        input_address = self.parse_offsets(input_address)
        if not input_address:
            return None, None, "输入的偏移量无效。"
        important_functions = self.read_file(self.info4_file)
        if important_functions is None:
            return None, None, "读取重点函数文件时出错。"
        lines = self.read_file(self.info_file)
        if lines is None:
            return None, None, "读取函数文件时出错。"
        matched_lines = self.filter_lines(input_address, lines)
        if not matched_lines:
            return None, None, "未找到匹配的函数信息。"
        message_im, message_vi, message = self.categorize_functions(matched_lines, important_functions)
        return (message_im, message_vi, message), None, None

class FuncExplorerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FuncExplorer GUI")
        self.setGeometry(100, 100, 900, 700)
        self.func_explorer = FuncExplorer()
        # Define registers here for GUI
        self.registers = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                          'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                          'rip', 'rflags'}
        self.init_ui()
    
    def init_ui(self):
        # Set main layout
        main_layout = QVBoxLayout()
        
        # Title Label
        title_label = QLabel("FuncExplorer")
        title_font = QFont("Arial", 24, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Input layout
        input_layout = QHBoxLayout()
        input_label = QLabel("输入函数名或函数头：")
        input_label.setFont(QFont("Arial", 12))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("请输入函数名或地址...")
        self.input_field.setFont(QFont("Arial", 12))
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_field)
        main_layout.addLayout(input_layout)
        
        # Search button
        self.search_button = QPushButton("搜索")
        self.search_button.setFont(QFont("Arial", 12))
        self.search_button.setIcon(QIcon.fromTheme("system-search"))
        self.search_button.clicked.connect(self.perform_search)
        main_layout.addWidget(self.search_button)
        
        # Scroll Area for results
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll_area)
        
        # Set layout
        self.setLayout(main_layout)
        
        # Apply styles
        self.apply_styles()
    
    def apply_styles(self):
        self.setStyleSheet("""
        QWidget {
            background-color: #f9f9f9;
        }
        QLabel {
            color: #333333;
        }
        QPushButton {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
        }
        QPushButton:hover {
            background-color: #45a049;
        }
        QLineEdit {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        QGroupBox {
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        """)
    
    def perform_search(self):
        # 清除之前的结果
        self.clear_results()
        user_input = self.input_field.text().strip()
        if not user_input:
            QMessageBox.warning(self, "输入错误", "请输入要查询的函数名或函数头。")
            return
        # 获取函数信息
        (message_im, message_vi, message), error, error_msg = self.func_explorer.get_function_info(user_input)
        if error:
            # 显示错误信息
            error_label = QLabel(error_msg)
            error_label.setFont(QFont("Arial", 12))
            error_label.setStyleSheet("color: red;")
            # 允许文本选择
            error_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.scroll_layout.addWidget(error_label)
            return
        if message_im:
            # 显示重点函数
            category_label = QLabel("以下是重点函数：")
            category_label.setFont(QFont("Arial", 14, QFont.Bold))
            category_label.setStyleSheet("color: #d9534f;")  # 红色
            self.scroll_layout.addWidget(category_label)
            for func_info in message_im:
                group_box = self.create_function_groupbox(func_info, is_important=True)
                self.scroll_layout.addWidget(group_box)
        if message_vi:
            # 显示虚函数
            category_label = QLabel("以下是虚函数：")
            category_label.setFont(QFont("Arial", 14, QFont.Bold))
            category_label.setStyleSheet("color: #5bc0de;")  # 蓝色
            self.scroll_layout.addWidget(category_label)
            for func_info in message_vi:
                group_box = self.create_function_groupbox(func_info, is_virtual=True)
                self.scroll_layout.addWidget(group_box)
        if message:
            # 显示普通函数
            category_label = QLabel("以下是普通函数：")
            category_label.setFont(QFont("Arial", 14, QFont.Bold))
            category_label.setStyleSheet("color: #5cb85c;")  # 绿色
            self.scroll_layout.addWidget(category_label)
            for func_info in message:
                group_box = self.create_function_groupbox(func_info)
                self.scroll_layout.addWidget(group_box)
        if not (message_im or message_vi or message):
            # 如果没有找到函数
            no_result_label = QLabel("未找到匹配的函数信息。")
            no_result_label.setFont(QFont("Arial", 12))
            no_result_label.setStyleSheet("color: red;")
            no_result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.scroll_layout.addWidget(no_result_label)
    
    def clear_results(self):
        # 移除所有子控件
        while self.scroll_layout.count():
            child = self.scroll_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    
    def create_function_groupbox(self, function_info, is_important=False, is_virtual=False):
        """创建一个显示函数信息的QGroupBox，并对函数定义进行高亮显示"""
        group_box = QGroupBox()
        group_box.setCheckable(True)
        group_box.setChecked(False)
        group_box.setStyleSheet("""
        QGroupBox {
            font: 14px Arial;
        }
        """)
        layout = QVBoxLayout()
        # 如果是重点函数，添加标签
        if is_important:
            important_label = QLabel("[此函数是重点函数*]")
            important_label.setFont(QFont("Arial", 12, QFont.Bold))
            important_label.setStyleSheet("color: #d9534f;")  # 红色
            important_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(important_label)
        
        if is_virtual:
            virtual_label = QLabel("[此函数是虚函数]")
            virtual_label.setFont(QFont("Arial", 12, QFont.Bold))
            virtual_label.setStyleSheet("color: #5bc0de;")  # 蓝色
            virtual_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(virtual_label)
        
        # 分析函数信息
        func_lines = function_info.split('\n')
        for func_line in func_lines:
            if func_line.startswith("[此函数是重点函数*]") or func_line.startswith("[此函数是虚函数]"):
                continue
            
            if '：' in func_line:
                key, value = func_line.split('：', 1)
            else:
                key, value = func_line, ""
            
            if key and value:
                if key == "函数定义":
                    # 对函数定义进行高亮处理
                    highlighted_def = self.highlight_function_definition(value)
                    func_label = QLabel(highlighted_def)
                    func_label.setFont(QFont("Consolas", 12))  # 使用等宽字体更美观
                    func_label.setStyleSheet("color: #333333;")
                    func_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    func_label.setTextFormat(Qt.RichText)
                else:
                    # 其他信息保持不变
                    func_label = QLabel(f"<b>{key}：</b>{value}")
                    func_label.setFont(QFont("Arial", 12))
                    func_label.setStyleSheet("color: #333333;")
                    func_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                
                layout.addWidget(func_label)
        
        group_box.setLayout(layout)
        return group_box
    
    def highlight_function_definition(self, func_def):
        """
        解析函数定义字符串，并返回带有HTML高亮的字符串。
        例如:
        Sexy::ButtonListener::ButtonPress(int theClickCount, int theId, ecx = ButtonListener* this)
        """
        # 定义颜色
        colors = {
            'class': '#28a745',      # 绿色
            'operator': '#ffffff',   # 白色
            'function': '#ffc107',   # 黄色
            'datatype': '#007bff',   # 蓝色
            'varname': '#000000',    # 黑色
            'register': '#ff4500',   # 橙红色
        }
        # 正则表达式解析
        # 例子：Sexy::ButtonListener::ButtonPress(int theClickCount, int theId, ecx = ButtonListener* this)
        pattern = re.compile(
            r'(?P<class>[\w:]+)::(?P<function>\w+)\s*\((?P<params>[^)]*)\)'
        )
        match = pattern.match(func_def)
        if not match:
            # 如果不匹配，返回原始字符串
            return func_def
        class_full = match.group('class')  # e.g., Sexy::ButtonListener
        function_name = match.group('function')  # e.g., ButtonPress
        params = match.group('params')  # e.g., int theClickCount, int theId, ecx = ButtonListener* this
        # 处理类名和'::'操作符
        class_parts = class_full.split('::')
        highlighted_class = ""
        for i, part in enumerate(class_parts):
            highlighted_class += f'<span style="color:{colors["class"]};">{part}</span>'
            if i < len(class_parts) - 1:
                highlighted_class += f'<span style="color:{colors["operator"]};">::</span>'
        # 处理函数名
        highlighted_function = f'<span style="color:{colors["function"]};">{function_name}</span>'
        # 处理参数
        highlighted_params = self.highlight_parameters(params, colors)
        # 组合最终的高亮字符串
        highlighted_def = f'{highlighted_class}::{highlighted_function}({highlighted_params})'
        return highlighted_def
    
    def highlight_single_parameter(self, param, colors):
        """
        高亮显示单个参数。
        例如:
        int theClickCount
        ecx = ButtonListener* this
        """
        # 检查是否是寄存器赋值（如 ecx = ButtonListener* this）
        register_pattern = re.compile(r'^(?P<reg>\w+)\s*=\s*(?P<value>.+)$')
        reg_match = register_pattern.match(param)
        if reg_match:
            reg = reg_match.group('reg')
            value = reg_match.group('value')
            # 仅当寄存器在集合中时才高亮
            if reg.lower() in self.registers:
                highlighted_reg = f'<span style="color:{colors["register"]};">{reg}</span>'
            else:
                highlighted_reg = f'<span style="color:{colors["varname"]};">{reg}</span>'
            highlighted_value = self.highlight_expression(value, colors)
            return f'{highlighted_reg} = {highlighted_value}'
        else:
            return self.highlight_expression(param, colors)
    
    def highlight_parameters(self, params, colors):
        """
        解析参数字符串，并返回带有HTML高亮的字符串。
        例如:
        int theClickCount, int theId, ecx = ButtonListener* this
        """
        # 分割参数
        param_list = [p.strip() for p in params.split(',')]
        highlighted_params = []
        for param in param_list:
            # 检查是否有默认值（如 ecx = ButtonListener* this）
            if '=' in param:
                highlighted_param = self.highlight_single_parameter(param, colors)
            else:
                highlighted_param = self.highlight_single_parameter(param, colors)
            highlighted_params.append(highlighted_param)
        
        return ', '.join(highlighted_params)
    
    def highlight_expression(self, expr, colors):
        """
        高亮显示表达式中的数据类型和变量名。
        例如:
        int theClickCount
        ButtonListener* this
        """
        # 定义常见的数据类型，可根据需要扩展
        data_types = [
            'void', 'int', 'float', 'double', 'char', 'bool', 'long', 'short',
            'unsigned', 'signed', 'const', 'static', 'ButtonListener', 'Plant',
            'Zombie', "SeedType", "Board*", "ZombieType", "Zombie*&", "Challenge*", "CutScene*"
        ]
        # 正则表达式分割数据类型和变量名
        # 处理指针和引用符号
        pattern = re.compile(r'(?P<type>\b(?:' + '|'.join(data_types) + r')\b[\w\s\*]*)\s+(?P<name>\w+)')
        match = pattern.match(expr)
        if match:
            type_part = match.group('type')
            name_part = match.group('name')
            # 高亮数据类型
            highlighted_type = f'<span style="color:{colors["datatype"]};">{type_part}</span>'
            # 高亮变量名
            highlighted_name = f'<span style="color:{colors["varname"]};">{name_part}</span>'
            return f'{highlighted_type} {highlighted_name}'
        else:
            # 如果不匹配，返回原始字符串
            return expr

def main():
    app = QApplication(sys.argv)
    gui = FuncExplorerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()