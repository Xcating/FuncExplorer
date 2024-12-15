import re
import sys
import logging
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QScrollArea, QGroupBox, QPlainTextEdit
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt

# 配置日志
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FuncExplorer:
    def __init__(self):
        base_path = Path(__file__).parent.resolve()
        self.info_file = base_path / 'functions.txt'
        self.important_functions_file = base_path / 'important_functions.txt'

    @staticmethod
    def clean_input(input_address):
        """清理输入地址，移除前缀和多余字符"""
        # 合并重复的模式
        patterns = r'^(#|/|查|找|看|函数|Function|function|Func|func|call|Call| )+'
        cleaned = re.sub(patterns, '', input_address).strip()
        return cleaned

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
                return [line.strip() for line in f if line.strip()]
        except Exception as err:
            logger.error(f"Error reading {file_path}: {err}", exc_info=True)
            return None

    def filter_lines(self, input_address, lines):
        """根据输入地址过滤匹配的行"""
        if re.fullmatch(r'^[0-9A-Fa-f]+$', input_address):
            try:
                input_number = int(input_address, 16)
            except ValueError:
                logger.error(f"Invalid hexadecimal input: {input_address}")
                return []
            matched_lines = [
                line for line in lines
                if len(line.split('\t')) >= 2 and
                self._is_within_range(line.split('\t')[0], input_number)
            ]
            return [matched_lines[-1]] if matched_lines else []
        else:
            keywords = [kw for kw in re.split(r'[\s,;，。]+', input_address) if kw]
            if keywords:
                # 使用非捕获组和所有关键字的前瞻断言
                regex = re.compile('(?=.*' + ')(?=.*'.join(map(re.escape, keywords)) + ')', re.IGNORECASE)
                return [line for line in lines if regex.search(line)][:1000]
        return []

    @staticmethod
    def _is_within_range(line_address, input_number):
        """检查地址是否在指定范围内"""
        try:
            current_number = int(line_address, 16)
            return input_number - 0xFFFF <= current_number <= input_number
        except ValueError:
            return False

    def categorize_functions(self, matched_lines, important_functions):
        """分类函数信息为重点函数、普通函数和虚函数"""
        important_set = set()
        for func in important_functions:
            try:
                important_set.add(int(func, 16))
            except ValueError:
                logger.warning(f"Invalid important function address: {func}")

        message_im = []
        message_vi = []
        message = []

        for line in matched_lines:
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            try:
                func_address = int(parts[0], 16)
            except ValueError:
                logger.warning(f"Invalid function address: {parts[0]}")
                continue

            is_important = func_address in important_set
            messages = self._construct_function_message(parts)

            if is_important:
                message_im.append(messages)
            else:
                if len(parts) > 6 and parts[6]:
                    message_vi.append(messages)
                else:
                    message.append(messages)

        return message_im, message_vi, message

    @staticmethod
    def _construct_function_message(parts):
        """构建函数信息字符串"""
        messages = (
            f"函数头：{parts[0]}\n"
            f"函数定义：{parts[1]}\n"
            f"返回与临时寄存器组：{parts[2]}\n"
        )
        stack_clean = parts[3].replace('0x', '').strip()
        if stack_clean:
            messages += f"函数清栈：add esp,{stack_clean} (十六进制)\n"
        messages += f"函数简介：{parts[4]}\n"
        if len(parts) > 6 and parts[6]:
            messages += f"{parts[6]}\n"
        return messages.replace(" ;", "\n ")

    def get_function_info(self, input_address):
        """主查询函数，返回分类后的函数信息列表"""
        try:
            cleaned_input = self.clean_input(input_address)
            parsed_input = self.parse_offsets(cleaned_input)
            if not parsed_input:
                return None, None, "输入的偏移量无效。"

            important_functions = self.read_file(self.important_functions_file)
            if important_functions is None:
                return None, None, "读取重点函数文件时出错。"

            lines = self.read_file(self.info_file)
            if lines is None:
                return None, None, "读取函数文件时出错。"

            matched_lines = self.filter_lines(parsed_input, lines)
            if not matched_lines:
                return None, None, "未找到匹配的函数信息。"

            message_im, message_vi, message = self.categorize_functions(matched_lines, important_functions)
            return (message_im, message_vi, message), None, None

        except Exception as e:
            logger.error("An unexpected error occurred in get_function_info:", exc_info=True)
            return None, None, "发生了一个意外错误。"


class FuncExplorerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FuncExplorer GUI")
        self.setGeometry(100, 100, 900, 800)  # 增加窗口高度
        self.func_explorer = FuncExplorer()

        # 定义寄存器集
        self.registers = {
            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
            'rip', 'rflags'
        }

        self.init_ui()

    def init_ui(self):
        """初始化用户界面"""
        main_layout = QVBoxLayout()

        # 标题标签
        title_label = QLabel("FuncExplorer")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        # 说明标签
        pyqt_label = QLabel("本软件项目使用了 PyQt5 构建图形界面")
        pyqt_label.setFont(QFont("Arial", 10))
        pyqt_label.setAlignment(Qt.AlignCenter)
        pyqt_label.setStyleSheet("color: #555555;")
        main_layout.addWidget(pyqt_label)

        # 输入布局
        input_layout = QHBoxLayout()
        input_label = QLabel("输入函数名或函数头：")
        input_label.setFont(QFont("Arial", 12))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("请输入函数名或地址...")
        self.input_field.setFont(QFont("Arial", 12))
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_field)
        main_layout.addLayout(input_layout)

        # 搜索按钮
        self.search_button = QPushButton("搜索")
        self.search_button.setFont(QFont("Arial", 12))
        self.search_button.setIcon(QIcon.fromTheme("system-search"))
        self.search_button.clicked.connect(self.perform_search)
        main_layout.addWidget(self.search_button)

        # 结果滚动区域
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll_area)

        self.setLayout(main_layout)
        self.apply_styles()

    def apply_styles(self):
        """应用样式表"""
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
                padding: 0 5px;
            }
            QPlainTextEdit {
                background-color: #272822;
                color: #f8f8f2;
                font-family: Consolas, "Courier New", monospace;
                font-size: 12px;
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 10px;
            }
        """)

    def perform_search(self):
        """执行搜索操作"""
        self.clear_results()
        user_input = self.input_field.text().strip()
        if not user_input:
            QMessageBox.warning(self, "输入错误", "请输入要查询的函数名或函数头。")
            return

        result, error, error_msg = self.func_explorer.get_function_info(user_input)
        if error:
            self._display_error(error_msg)
            return

        if result:
            message_im, message_vi, message = result
            if message_im:
                self._display_category("以下是重点函数：", message_im, category_color="#d9534f")
            if message_vi:
                self._display_category("以下是虚函数：", message_vi, category_color="#5bc0de")
            if message:
                self._display_category("以下是普通函数：", message, category_color="#5cb85c")

        if not any([result[0], result[1], result[2]]):
            self._display_no_results()

    def clear_results(self):
        """清除之前的搜索结果"""
        while self.scroll_layout.count():
            child = self.scroll_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def _display_error(self, message):
        """显示错误信息"""
        error_label = QLabel(message)
        error_label.setFont(QFont("Arial", 12))
        error_label.setStyleSheet("color: red;")
        error_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.scroll_layout.addWidget(error_label)

    def _display_no_results(self):
        """显示无结果信息"""
        no_result_label = QLabel("未找到匹配的函数信息。")
        no_result_label.setFont(QFont("Arial", 12))
        no_result_label.setStyleSheet("color: red;")
        no_result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.scroll_layout.addWidget(no_result_label)

    def _display_category(self, title, messages, category_color):
        """显示特定类别的函数信息"""
        category_label = QLabel(title)
        category_label.setFont(QFont("Arial", 14, QFont.Bold))
        category_label.setStyleSheet(f"color: {category_color};")
        self.scroll_layout.addWidget(category_label)
        for func_info in messages:
            group_box, asm_text = self.create_function_groupbox(func_info, 
                                                                 is_important=(category_color == "#d9534f"),
                                                                 is_virtual=(category_color == "#5bc0de"))
            self.scroll_layout.addWidget(group_box)
            if asm_text:
                self.scroll_layout.addWidget(asm_text)

    def create_function_groupbox(self, function_info, is_important=False, is_virtual=False):
        """创建一个显示函数信息的QGroupBox，并对函数定义进行高亮显示"""
        group_box = QGroupBox()
        group_box.setCheckable(True)
        group_box.setChecked(False)
        group_box.setStyleSheet("QGroupBox { font: 14px Arial; }")
        layout = QVBoxLayout()

        # 添加重点函数或虚函数标签
        if is_important:
            label = QLabel("[此函数是重点函数*]")
            label.setFont(QFont("Arial", 12, QFont.Bold))
            label.setStyleSheet("color: #d9534f;")
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(label)
        if is_virtual:
            label = QLabel("[此函数是虚函数]")
            label.setFont(QFont("Arial", 12, QFont.Bold))
            label.setStyleSheet("color: #5bc0de;")
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(label)

        # 分析函数信息
        func_lines = function_info.split('\n')
        func_def = ""
        func_address = ""
        for func_line in func_lines:
            if func_line.startswith("函数头："):
                func_address = func_line.split("：", 1)[1].strip()
                label = QLabel(f"函数头：{func_address}")
                label.setFont(QFont("Arial", 12))
                label.setStyleSheet("color: #333333;")
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                layout.addWidget(label)
            elif func_line.startswith("函数定义："):
                func_def = func_line.split("：", 1)[1].strip()
                highlighted_def = self.highlight_function_definition(func_def)
                label = QLabel(highlighted_def)
                label.setFont(QFont("Consolas", 12))
                label.setStyleSheet("color: #333333;")
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                label.setTextFormat(Qt.RichText)
                layout.addWidget(label)
            elif func_line.startswith("返回与临时寄存器组："):
                return_registers = func_line.split("：", 1)[1].strip()
                label = QLabel(f"返回与临时寄存器组：{return_registers}")
                label.setFont(QFont("Arial", 12))
                label.setStyleSheet("color: #333333;")
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                layout.addWidget(label)
            elif func_line.startswith("函数清栈："):
                stack_clean = func_line.split("：", 1)[1].strip()
                label = QLabel(f"函数清栈：{stack_clean}")
                label.setFont(QFont("Arial", 12))
                label.setStyleSheet("color: #333333;")
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                layout.addWidget(label)
            elif func_line.startswith("函数简介："):
                func_intro = func_line.split("：", 1)[1].strip()
                label = QLabel(f"函数简介：{func_intro}")
                label.setFont(QFont("Arial", 12))
                label.setStyleSheet("color: #333333;")
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                layout.addWidget(label)
            else:
                extra_info = func_line.strip()
                if extra_info:
                    label = QLabel(extra_info)
                    label.setFont(QFont("Arial", 12))
                    label.setStyleSheet("color: #333333;")
                    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                    layout.addWidget(label)

        group_box.setLayout(layout)

        # 生成汇编代码
        asm_example = self.generate_asm_example(func_def, func_address)
        asm_text = None
        if asm_example:
            asm_label = QLabel("函数用例（伪C __asm）：")
            asm_label.setFont(QFont("Arial", 12, QFont.Bold))
            asm_label.setStyleSheet("color: #555555;")
            layout.addWidget(asm_label)

            asm_text = QPlainTextEdit()
            asm_text.setPlainText(asm_example)
            asm_text.setReadOnly(True)
            asm_text.setMinimumHeight(150)
            layout.addWidget(asm_text)

        return group_box, asm_text

    def generate_asm_example(self, func_def, func_address):
        """
        解析函数定义字符串，并生成伪C++ __asm代码示例。
        """
        if not func_def or not func_address:
            return None

        # 确保地址以0x开头
        call_addr = func_address if func_address.lower().startswith("0x") else f"0x{func_address}"

        # 解析函数定义
        pattern = re.compile(
            r'(?P<class>[\w:]+)::(?P<function>\w+)\s*\((?P<params>[^)]*)\)'
        )
        match = pattern.match(func_def)
        if not match:
            return None

        class_full = match.group('class')
        function_name = match.group('function')
        params = match.group('params')

        # 分割参数
        param_list = [p.strip() for p in params.split(',') if p.strip()]
        push_params = []
        mov_registers = []

        for param in param_list:
            # 检查寄存器赋值
            reg_assign_match = re.match(r'^(?P<reg>\w+)\s*=\s*(?P<value>.+)$', param)
            if reg_assign_match:
                reg = reg_assign_match.group('reg')
                value = reg_assign_match.group('value')
                # 处理数组参数
                array_match = re.match(r'^[\w\*]+\s+(?P<name>\w+)(\s*\[\s*\])+$', value)
                if array_match:
                    var_name = array_match.group('name')
                    if reg.lower() in self.registers:
                        mov_registers.append((reg, var_name))
                else:
                    # 提取变量名称
                    var_parts = value.strip().split()
                    variable_name = var_parts[-1] if var_parts else value
                    if reg.lower() in self.registers:
                        mov_registers.append((reg, variable_name))
            else:
                # 普通参数压栈
                array_match = re.match(r'^[\w\*]+\s+(?P<name>\w+)(\s*\[\s*\])+$', param)
                if array_match:
                    var_name = array_match.group('name')
                    push_params.append(var_name)
                else:
                    # 提取参数名称
                    parts = param.split()
                    if len(parts) >= 2:
                        param_name = parts[-1]
                        push_params.append(param_name)
                    else:
                        push_params.append(param)

        # 生成 asm 代码
        asm_lines = [
            f"void* CallAddr = (void*){call_addr};",
            "__asm",
            "{"
        ]

        # 逆序压栈
        for param in reversed(push_params):
            asm_lines.append(f"    push {param}")

        # 移动寄存器
        for reg, value in mov_registers:
            asm_lines.append(f"    mov {reg}, {value}")

        asm_lines.append(f"    call CallAddr")
        asm_lines.append("}")

        return "\n".join(asm_lines)

    def highlight_function_definition(self, func_def):
        """
        解析函数定义字符串，并返回带有HTML高亮的字符串。
        """
        colors = {
            'class': '#28a745',       # 绿色
            'operator': '#000000',    # 黑色
            'function': '#ffc107',    # 黄色
            'datatype': '#007bff',    # 蓝色
            'varname': '#000000',     # 黑色
            'register': '#ff4500',    # 橙红色
        }

        pattern = re.compile(
            r'(?P<class>[\w:]+)::(?P<function>\w+)\s*\((?P<params>[^)]*)\)'
        )
        match = pattern.match(func_def)
        if not match:
            return func_def

        class_full = match.group('class')
        function_name = match.group('function')
        params = match.group('params')

        # 高亮类名和作用域运算符
        class_parts = class_full.split('::')
        highlighted_class = ''.join(
            [f'<span style="color:{colors["class"]};">{part}</span>' +
             (f'<span style="color:{colors["operator"]};">::</span>' if i < len(class_parts)-1 else '')
             for i, part in enumerate(class_parts)]
        )

        # 高亮函数名
        highlighted_function = f'<span style="color:{colors["function"]};">{function_name}</span>'

        # 高亮参数
        highlighted_params = self.highlight_parameters(params, colors)

        return f'{highlighted_class}::{highlighted_function}({highlighted_params})'

    def highlight_single_parameter(self, param, colors):
        """
        高亮显示单个参数。
        """
        register_match = re.match(r'^(?P<reg>\w+)\s*=\s*(?P<value>.+)$', param)
        if register_match:
            reg = register_match.group('reg')
            value = register_match.group('value')
            reg_color = colors["register"] if reg.lower() in self.registers else colors["varname"]
            highlighted_reg = f'<span style="color:{reg_color};">{reg}</span>'
            highlighted_value = self.highlight_expression(value, colors)
            return f'{highlighted_reg} = {highlighted_value}'
        else:
            return self.highlight_expression(param, colors)

    def highlight_parameters(self, params, colors):
        """
        解析参数字符串，并返回带有HTML高亮的字符串。
        """
        param_list = [p.strip() for p in params.split(',') if p.strip()]
        highlighted_params = [self.highlight_single_parameter(p, colors) for p in param_list]
        return ', '.join(highlighted_params)

    def highlight_expression(self, expr, colors):
        """
        高亮显示表达式中的数据类型和变量名。
        """
        data_types = [
            'void', 'int', 'float', 'double', 'char', 'bool', 'long', 'short',
            'unsigned', 'signed', 'const', 'static', 'Zombie', 'Plant',
            'ButtonListener', 'SeedType', 'Board', 'ZombieType',
            'Challenge', 'CutScene'
        ]
        pattern = re.compile(
            r'(?P<type>\b(?:' + '|'.join(map(re.escape, data_types)) + r')\b[\w\s\*&]*)\s+(?P<name>[\w\[\]]+)'
        )
        match = pattern.match(expr)
        if match:
            type_part = match.group('type')
            name_part = match.group('name')
            highlighted_type = f'<span style="color:{colors["datatype"]};">{type_part}</span>'
            highlighted_name = f'<span style="color:{colors["varname"]};">{name_part}</span>'
            return f'{highlighted_type} {highlighted_name}'
        return expr

    @staticmethod
    def main():
        app = QApplication(sys.argv)
        gui = FuncExplorerGUI()
        gui.show()
        sys.exit(app.exec_())


if __name__ == "__main__":
    FuncExplorerGUI.main()