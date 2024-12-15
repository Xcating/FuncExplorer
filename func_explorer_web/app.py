import re
import logging
from pathlib import Path
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

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
                    return None
            input_address = ','.join([format(offset, 'X') for offset in offsets])
        return input_address

    def read_file(self, file_path):
        """读取文件内容并返回行列表"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f]
        except Exception as err:
            logger.error(f"Error reading {file_path}: {err}")
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
        """分类函数信息为重要函数、普通函数和虚函数"""
        message_im = []
        message_vi = []
        message = []
        for line in matched_lines:
            messages = {}
            parts = line.split('\t')
            if len(parts) < 5:
                continue
            # 判断是否为重要函数
            is_important_function = False
            for te_line in important_functions:
                try:
                    a = int(te_line, 16)
                    b = int(parts[0], 16)
                    if a == b:
                        messages['important'] = True
                        is_important_function = True
                        break
                except ValueError:
                    continue
            # 拼接函数信息
            messages['函数头'] = parts[0]
            messages['函数定义'] = parts[1]
            messages['函数返回值'] = parts[2]
            parts[3] = parts[3].replace('0x', '').strip()
            if parts[3]:
                messages['函数清栈'] = f"add esp,{parts[3]} (十六进制)"
            messages['函数简介'] = parts[4]
            if len(parts) > 6 and parts[6]:
                messages['其他信息'] = parts[6]
            # 分类存储
            if is_important_function:
                message_im.append(messages)
            else:
                if len(parts) > 6 and parts[6]:
                    messages['虚函数'] = True
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
            return None, None, "读取重要函数文件时出错。"
        lines = self.read_file(self.info_file)
        if lines is None:
            return None, None, "读取函数文件时出错。"
        matched_lines = self.filter_lines(input_address, lines)
        if not matched_lines:
            return None, None, "未找到匹配的函数信息。"
        message_im, message_vi, message = self.categorize_functions(matched_lines, important_functions)
        return (message_im, message_vi, message), None, None

# Initialize FuncExplorer
func_explorer = FuncExplorer()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_input = request.form.get('search_input', '').strip()
        if not user_input:
            return render_template('index.html', error="请输入要查询的函数名或函数头。")
        
        (message_im, message_vi, message), error, error_msg = func_explorer.get_function_info(user_input)
        
        if error:
            return render_template('index.html', error=error_msg)
        
        return render_template('index.html', 
                               important_functions=message_im, 
                               virtual_functions=message_vi, 
                               normal_functions=message)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)