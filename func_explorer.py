import re
import os
import logging
from pathlib import Path

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
        """分类函数信息为重要函数、普通函数和虚函数"""
        message_im = []
        message_vi = []
        message = []

        for line in matched_lines:
            messages = ""
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
                        messages += "[此函数是重要函数*]\n"
                        is_important_function = True
                        break
                except ValueError:
                    continue

            # 拼接函数信息
            messages += f"函数头：{parts[0]}\n函数定义：{parts[1]}\n函数返回值：{parts[2]}\n"
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

    def format_result(self, message_im, message_vi, message):
        """格式化最终结果"""
        merged_array = ['找到了这些函数：']
        if message_im:
            merged_array.append('以下是重要函数：')
            merged_array.extend(message_im)
        if message:
            merged_array.append('以下是普通函数：')
            merged_array.extend(message)
        if message_vi:
            merged_array.append('以下是虚函数：')
            merged_array.extend(message_vi)

        # 添加序号
        s_index = 1
        for i in range(1, len(merged_array)):
            if merged_array[i] and not any(sub in merged_array[i] for sub in ['以下是普通函数', '以下是虚函数', '以下是重要函数']):
                merged_array[i] = f"{s_index}:\n{merged_array[i]}"
                s_index += 1

        return '\n'.join(merged_array)

    def get_function_info(self, input_address):
        """主查询函数"""
        input_address = self.clean_input(input_address)
        input_address = self.parse_offsets(input_address)

        if not input_address:
            return "输入的偏移量无效。"

        important_functions = self.read_file(self.info4_file)
        if important_functions is None:
            return "读取重要函数文件时出错。"

        lines = self.read_file(self.info_file)
        if lines is None:
            return "读取函数文件时出错。"

        matched_lines = self.filter_lines(input_address, lines)
        if not matched_lines:
            return "未找到匹配的函数信息。"

        message_im, message_vi, message = self.categorize_functions(matched_lines, important_functions)
        return self.format_result(message_im, message_vi, message)

def main():
    func_explorer = FuncExplorer()
    user_input = input("请输入要查询的函数名或函数头：")
    result = func_explorer.get_function_info(user_input)
    print(result)

if __name__ == "__main__":
    main()