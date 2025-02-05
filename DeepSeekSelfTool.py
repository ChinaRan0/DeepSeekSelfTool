import sys
import os
import json
import requests
import re
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QTextEdit, QPushButton, QLabel, QHBoxLayout,
                             QSplitter, QScrollArea, QTabWidget, QFrame,QCheckBox ,QSizePolicy,QComboBox,QFileDialog,QProgressBar)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette, QLinearGradient
import config
import glob
from openai import OpenAI
from config import THEMES


os.environ["QT_IM_MODULE"] = "none"


class APIAdapter:
    def __init__(self):
        self.api_type = config.API_TYPE # Supported values: "deepseek", "qwen", "openai", "ollama"

        self.api_endpoints = {
            "deepseek": "https://api.deepseek.com/v1",
            "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
            "openai": getattr(config, "OPENAI_BASE_URL", "https://api.openai.com/v1"),
        }

        self.api_keys = {
            key: getattr(config, f"{key.upper()}_API_KEY", None)
            for key in self.api_endpoints
        }
        self.api_keys["ollama"] = "OLLAMA" # required, but not used

        self.models = {
            "ollama": getattr(config, "OLLAMA_MODEL", "deepseek-coder"),
            "deepseek": getattr(config, "DEEPSEEK_MODEL", "deepseek-chat"),
            "qwen": getattr(config, "QWEN_MODEL", "qwen-turbo"),
            "openai": getattr(config, "OPENAI_MODEL", "gpt-4o-mini"),
        }

        if self.api_type in self.api_endpoints:
            self.api_endpoint = self.api_endpoints[self.api_type]
            self.api_key = self.api_keys.get(self.api_type)
            self.model = self.models[self.api_type]
        elif self.api_type == "ollama":
            self.api_endpoint = config.OLLAMA_API_URL
            self.model = getattr(config, "OLLAMA_MODEL", "deepseek-coder")
        else:
            raise ValueError(f"Unsupported API type: {self.api_type}")
        print(f"API类型: {self.api_type}")
        print(f"API地址: {self.api_endpoint}")
        print(f"模型: {self.model}")


    def chat_completion(self, prompt, temperature=0.3):
        try:
            return self._send_request(self.model, prompt, temperature)
        except Exception as e:
            raise ValueError(f"API请求失败: {str(e)}")

    def _send_request(self, model, prompt, temperature):
        if self.api_type in ["deepseek", "qwen", "openai"]:
            client = OpenAI(
                api_key=self.api_key,
                base_url=self.api_endpoint
            )
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=model,
                temperature=temperature,
                stream=False,
            )
            return chat_completion.choices[0].message.content
        
        elif self.api_type == "ollama":
            headers = {"Content-Type": "application/json"}
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False
            }
            response = requests.post(self.api_endpoint, headers=headers, json=payload, timeout=60)
            
            response.raise_for_status()
            data = response.json()
            return self._clean_ollama_response(data["message"]["content"])
        else:
            raise ValueError(f"Unsupported API type: {self.api_type}")
        

    def _clean_ollama_response(self, content):
        return re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()


class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(str, bool)

    def __init__(self, http_data, parent=None):
        super().__init__(parent)
        self.http_data = http_data
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请进行网络安全分析。请严格按照以下步骤执行：
1. 分析以下HTTP请求的各个组成部分
2. 识别是否存在SQL注入、XSS、CSRF、反序列化、文件上传、路径遍历、OWASPTop10、等常见攻击特征
3. 检查User-Agent等头部信息是否可疑
4. 最终结论：是否为攻击流量（是/否）

请用中文按以下格式响应：
【分析结果】是/否
【依据】简明扼要列出技术依据

HTTP请求数据：
{self.http_data}"""

            result = self.api.chat_completion(prompt)
            is_attack = "【分析结果】是" in result
            self.analysis_complete.emit(result, is_attack)

        except Exception as e:
            self.analysis_complete.emit(f"错误发生: {str(e)}", False)

class DecodingThread(QThread):
    decoding_complete = pyqtSignal(str)

    def __init__(self, encoded_str, parent=None):
        super().__init__(parent)
        self.encoded_str = encoded_str
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请完整分析并解码以下字符串，要求：
1. 识别所有可能的编码方式（包括嵌套编码）
2. 通过自己重新编码，确认自己解码正确
3. 展示完整的解码过程
4. 输出最终解码结果

原始字符串：{self.encoded_str}

请用中文按以下格式响应：
【编码分析】列出检测到的编码类型及层级
【解码过程】逐步展示解码步骤
【最终结果】解码后的明文内容"""

            result = self.api.chat_completion(prompt)
            self.decoding_complete.emit(result)

        except Exception as e:
            self.decoding_complete.emit(f"解码错误: {str(e)}")

class ProcessAnalysisThread(QThread):
    process_complete = pyqtSignal(str)

    def __init__(self, process_data, parent=None):
        super().__init__(parent)
        self.process_data = process_data
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""你是一个Windows/Linux进程分析工程师，要求：
1. 用户将输出tasklist或者ps aux的结果
2. 帮助用户分析输出你所有认识的进程信息
3. 识别可能的恶意进程
4. 识别杀毒软件进程
5. 识别其他软件进程

tasklist或者ps aux的结果：{self.process_data}

按优先级列出需要关注的进程
【可疑进程】
【杀软进程】
【第三方软件进程】
给出具体操作建议：
• 安全进程的可终止性评估
"""

            result = self.api.chat_completion(prompt)
            self.process_complete.emit(result)

        except Exception as e:
            self.process_complete.emit(f"进程分析错误: {str(e)}")

class JsAuditThread(QThread):
    audit_complete = pyqtSignal(str)

    def __init__(self, js_code, parent=None):
        super().__init__(parent)
        self.js_code = js_code
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请对以下JavaScript代码进行完整的安全审计，要求：
1. 识别XSS、CSRF、不安全的DOM操作、敏感信息泄露、eval使用等安全问题
2. 检查第三方库的安全性和版本漏洞
3. 分析代码逻辑漏洞
4. 提供修复建议

请用中文按以下格式响应：
【高危漏洞】列出高危安全问题及位置
【中低危问题】列出中低风险问题
【修复建议】提供具体修复方案

JavaScript代码：
{self.js_code}"""

            result = self.api.chat_completion(prompt)
            self.audit_complete.emit(result)

        except Exception as e:
            self.audit_complete.emit(f"审计错误: {str(e)}")

class HttpToPythonThread(QThread):
    conversion_complete = pyqtSignal(str)

    def __init__(self, http_request, parent=None):
        super().__init__(parent)
        self.http_request = http_request
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""你是一个专业Python开发助手，请将以下HTTP请求转换为规范的Python代码（使用requests库）。按以下步骤处理：
要求：
1.用户输入：完整请求头（包含Content-Type和Authorization）
2.用户输入：完整的请求题（包含请求方法、URL和参数）
3.用户输入：请求体的内容（如果有）
4.默认不进行SSL验证
5.输出：完整的Python代码，包含请求头、请求体和请求方法

请用中文按以下格式响应：
【Python代码】输出转换后的Python代码，不使用markdown格式，不要有其他多余的输出

这是用户输入的内容：
{self.http_request}"""

            result = self.api.chat_completion(prompt)
            self.conversion_complete.emit(result)

        except Exception as e:
            self.conversion_complete.emit(f"转换错误: {str(e)}")

class TextProcessThread(QThread):
    process_complete = pyqtSignal(str)

    def __init__(self, source_text, sample_text, parent=None):
        super().__init__(parent)
        self.source_text = source_text
        self.sample_text = sample_text
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""写python代码，请根据提供的样本格式，将源文本转换为与样本相同的格式。要求：
1. 分析样本文本的结构和格式特征
2. 保持源文本的核心内容不变
3. 按照样本的格式要求重新组织内容
4. 确保转换后的文本与样本格式完全一致
5.最后输出转换两文本的python代码脚本，不要有其他多余的输出。

样本文本：
{self.sample_text}

源文本：
{self.source_text}

请直接输出python脚本，不要包含任何解释或说明。不使用markdown格式"""

            result = self.api.chat_completion(prompt)
            self.process_complete.emit(result)

        except Exception as e:
            self.process_complete.emit(f"文本处理错误: {str(e)}")

class RegexGenThread(QThread):
    regex_complete = pyqtSignal(str)

    def __init__(self, source_text, sample_text, parent=None):
        super().__init__(parent)
        self.source_text = source_text
        self.sample_text = sample_text
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请根据提供的样本格式，通过源文本生成正则表达式为与样本相同的内容。要求：
1. 分析样本文本的结构和格式特征
2. 保持源文本的核心内容不变
3. 生成多个正则表达式
4. 保证可以通过正则表达式匹配到样本文件中的内容

样本文本：
{self.sample_text}

源文本：
{self.source_text}

请直接输出生成的多个正则表达式，不要包含任何解释或说明，不要使用markdown格式输出"""

            result = self.api.chat_completion(prompt)
            self.regex_complete.emit(result)

        except Exception as e:
            self.regex_complete.emit(f"正则表达式生成错误: {str(e)}")

class WebShellAnalysisThread(QThread):
    analysis_complete = pyqtSignal(str, bool)

    def __init__(self, file_content, parent=None):
        super().__init__(parent)
        self.file_content = file_content
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请分析以下文件内容是否为WebShell或内存马。要求：
1. 检查PHP/JSP/ASP等WebShell特征（如加密函数、执行系统命令、文件操作）
2. 识别内存马特征（如无文件落地、进程注入、异常网络连接）
3. 分析代码中的可疑功能（如命令执行、文件上传、信息收集）
4. 检查混淆编码、加密手段等规避技术
5. 最终结论：是否为恶意软件（是/否）

请用中文按以下格式响应：
【分析结果】是/否
【恶意类型】WebShell/内存马/其他
【技术特征】列出检测到的技术指标
【风险等级】高/中/低

文件内容：
{self.file_content}"""

            result = self.api.chat_completion(prompt)
            is_malicious = "【分析结果】是" in result
            self.analysis_complete.emit(result, is_malicious)

        except Exception as e:
            self.analysis_complete.emit(f"错误发生: {str(e)}", False)

class TranslationThread(QThread):
    translation_complete = pyqtSignal(str)

    def __init__(self, text, source_lang, target_lang, parent=None):
        super().__init__(parent)
        self.text = text
        self.source_lang = source_lang
        self.target_lang = target_lang
        self.api = APIAdapter()

    def run(self):
        try:
            prompt = f"""请将以下文本从{self.source_lang}专业地翻译成{self.target_lang}。要求：
1. 保持技术术语准确性（特别是网络安全相关词汇）
2. 保留代码格式和变量名
3. 正确处理专业缩写（如XSS、SQLi等）
4. 输出仅需翻译结果，无需额外说明

待翻译内容：
{self.text}"""

            result = self.api.chat_completion(prompt)
            self.translation_complete.emit(result)

        except Exception as e:
            self.translation_complete.emit(f"翻译错误: {str(e)}")

class SourceCodeAuditThread(QThread):
    audit_complete = pyqtSignal(str)
    progress_updated = pyqtSignal(int)

    def __init__(self, files, parent=None):
        super().__init__(parent)
        self.files = files
        self.api = APIAdapter()

    def run(self):
        total_files = len(self.files)
        total_steps = total_files + 2  # 总步骤 = 文件数 + 2
        audit_results = []
        
        # ================= 阶段1：处理所有文件 =================
        for i, file_path in enumerate(self.files):
            try:
                # 文件读取
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception as e:
                    audit_results.append(f"【文件读取失败】{os.path.basename(file_path)}\n错误原因：{str(e)}")
                    continue

                # 更新进度（每个文件占1步）
                current_step = i + 1
                progress = int( (current_step / total_steps) * 100 )
                self.progress_updated.emit(progress)

                # API请求
                try:
                    prompt = f"""【强制指令】你是一个专业的安全审计AI，请按以下要求分析代码：
        
1. 漏洞分析流程：
   1.1 识别潜在风险点（SQL操作、文件操作、用户输入点、文件上传漏洞、CSRF、SSRF、XSS、RCE、OWASP top10等漏洞）
   1.2 验证漏洞可利用性
   1.3 按CVSS评分标准评估风险等级

2. 输出规则：
   - 仅输出确认存在的高危/中危漏洞
   - 使用严格格式：[风险等级] 类型 - 位置:行号 - 50字内描述
   - 禁止解释漏洞原理
   - 禁止给出修复建议
   - 每文件最多报告3个最严重问题

3. 输出示例（除此外不要有任何输出）：
   [高危] SQL注入 - {os.path.basename(file_path)}:32 - 未过滤的$_GET参数直接拼接SQL查询
   [中危] XSS - {os.path.basename(file_path)}:15 - 未转义的userInput输出到HTML

4. 当前代码（仅限分析）：
{content[:3000]}"""  # 限制每个文件内容长度

                    result = self.api.chat_completion(prompt)
                    audit_results.append(result)

                except Exception as e:
                    audit_results.append(
                        f"【API请求失败】{os.path.basename(file_path)}\n"
                        f"错误类型：{type(e).__name__}\n"
                        f"错误详情：{str(e)}"
                    )

            except Exception as e:  # 全局异常兜底
                audit_results.append(
                    f"【未知错误】{os.path.basename(file_path)}\n"
                    f"错误类型：{type(e).__name__}\n"
                    f"错误详情：{str(e)}"
                )

        # ================= 阶段2：结果汇总 =================
        try:
            # 更新进度到 N+1 步（汇总开始）
            self.progress_updated.emit( int( (total_files + 1) / total_steps * 100 ) )
            
            # 生成汇总结果
            if len(audit_results) == 0:
                final_result = "⚠️ 所有文件处理均失败，请检查网络连接和API密钥"
            else:
                audit_results_str = '\n'.join(audit_results)
                final_prompt = f"""请综合以下审计结果，按危险等级分类整理：
{audit_results_str}

要求：
1. 按【高危】【中危】【低危】三级分类
2. 每个漏洞注明文件名和行号
3. 同类漏洞合并显示
4. 不使用markdown格式，直接输出文本"""

                final_result = self.api.chat_completion(final_prompt)
                final_result += "\n\n--- 原始数据备份 ---\n" + "\n".join(audit_results)

        except Exception as e:
            final_result = (
                "⚠️ 汇总阶段失败，以下是各文件独立分析结果：\n\n" 
                + "\n".join(audit_results) 
                + f"\n\n汇总错误：{str(e)}"
            )

        # ================= 阶段3：最终提交 =================
        # 强制进度到100%后才发送结果
        self.progress_updated.emit(100)  # 最后一步
        self.audit_complete.emit(final_result)  # 此时必定100%

class CyberSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setStyleSheet(self.get_stylesheet())

    def init_ui(self):
        self.setWindowTitle('DeepSeek 安全分析平台 公众号:知攻善防实验室 By:ChinaRan404')
        self.setGeometry(300, 300, 1200, 800)
        self.setMinimumSize(QSize(1200, 800))

        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # 创建主布局
        main_layout = QVBoxLayout(main_widget)

        # 添加标签页组件
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # 创建底部主题选择器容器
        bottom_widget = QWidget()
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(5, 5, 5, 5)

        # 添加弹簧以推动主题选择器到右侧
        bottom_layout.addStretch()

        # 添加主题选择下拉框
        theme_label = QLabel("主题：")
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(list(THEMES.keys()))
        self.theme_selector.currentTextChanged.connect(self.change_theme)
        
        bottom_layout.addWidget(theme_label)
        bottom_layout.addWidget(self.theme_selector)

        main_layout.addWidget(bottom_widget)

        self.create_traffic_analysis_tab()
        self.create_js_audit_tab()
        self.create_process_analysis_tab()
        self.create_http_conversion_tab()
        self.create_text_processing_tab()
        self.create_regex_gen_tab()
        self.create_webshell_tab()  # 添加这行
        self.create_translation_tab()
        self.create_source_audit_tab()
    def create_scroll_textedit(self, placeholder="", read_only=True):
        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        
        text_edit = QTextEdit()
        text_edit.setPlaceholderText(placeholder)
        text_edit.setReadOnly(read_only)
        text_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(text_edit)
        
        layout.addWidget(scroll_area)
        return frame, text_edit

    def create_traffic_analysis_tab(self):
        tab = QWidget()
        splitter = QSplitter(Qt.Horizontal)
        layout = QHBoxLayout(tab)
        layout.addWidget(splitter)

        # 左侧分析区域
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("网络流量智能分析系统", font=QFont("Arial", 20, QFont.Bold)))

        _, self.traffic_input = self.create_scroll_textedit("粘贴HTTP请求数据...", False)
        left_layout.addWidget(QLabel("请输入HTTP请求数据:"))
        left_layout.addWidget(self.traffic_input)

        self.analyze_btn = QPushButton("开始智能分析", clicked=self.start_traffic_analysis)
        left_layout.addWidget(self.analyze_btn)

        _, self.traffic_result = self.create_scroll_textedit()
        left_layout.addWidget(QLabel("AI分析结果:"))
        left_layout.addWidget(self.traffic_result)

        # 右侧解码区域
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("AI全智能解码", font=QFont("Arial", 16)))

        _, self.decode_input = self.create_scroll_textedit("输入需要解码的字符串...", False)
        right_layout.addWidget(QLabel("待解码内容:"))
        right_layout.addWidget(self.decode_input)

        self.decode_btn = QPushButton("AI智能解码", clicked=self.start_decoding)
        right_layout.addWidget(self.decode_btn)

        _, self.decode_result = self.create_scroll_textedit()
        right_layout.addWidget(QLabel("解码结果:"))
        right_layout.addWidget(self.decode_result)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        self.tab_widget.addTab(tab, "流量分析")

    def create_js_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("JavaScript代码安全审计", font=QFont("Arial", 20, QFont.Bold)))

        _, self.js_input = self.create_scroll_textedit("粘贴JavaScript代码...", False)
        layout.addWidget(QLabel("输入待审计代码:"))
        layout.addWidget(self.js_input)

        self.js_audit_btn = QPushButton("开始安全审计", clicked=self.start_js_audit)
        layout.addWidget(self.js_audit_btn)

        _, self.js_result = self.create_scroll_textedit()
        layout.addWidget(QLabel("审计结果:"))
        layout.addWidget(self.js_result)

        self.tab_widget.addTab(tab, "JS审计")

    def create_process_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("进程分析系统", font=QFont("Arial", 20, QFont.Bold)))

        _, self.process_input = self.create_scroll_textedit("粘贴tasklist或ps aux信息...", False)
        layout.addWidget(QLabel("输入进程列表:"))
        layout.addWidget(self.process_input)

        self.process_btn = QPushButton("开始进程分析", clicked=self.start_process_analysis)
        layout.addWidget(self.process_btn)

        _, self.process_result = self.create_scroll_textedit()
        layout.addWidget(QLabel("分析结果:"))
        layout.addWidget(self.process_result)

        self.tab_widget.addTab(tab, "进程分析")

    def create_http_conversion_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("HTTP转Python代码", font=QFont("Arial", 20, QFont.Bold)))

        _, self.http_input = self.create_scroll_textedit("粘贴HTTP请求...", False)
        layout.addWidget(QLabel("输入HTTP请求:"))
        layout.addWidget(self.http_input)

        self.convert_btn = QPushButton("开始转换", clicked=self.start_http_conversion)
        layout.addWidget(self.convert_btn)

        _, self.conversion_result = self.create_scroll_textedit()
        layout.addWidget(QLabel("转换结果:"))
        layout.addWidget(self.conversion_result)

        self.tab_widget.addTab(tab, "HTTP转Python")

    def create_text_processing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("AI文本格式转换", font=QFont("Arial", 20, QFont.Bold)))

        columns = QWidget()
        column_layout = QHBoxLayout(columns)

        # 左侧输入
        left = QWidget()
        left_layout = QVBoxLayout(left)
        _, self.text_source = self.create_scroll_textedit("源文本...", False)
        left_layout.addWidget(QLabel("源文本:"))
        left_layout.addWidget(self.text_source)
        _, self.text_sample = self.create_scroll_textedit("样本格式...", False)
        left_layout.addWidget(QLabel("样本格式:"))
        left_layout.addWidget(self.text_sample)

        # 右侧结果
        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.text_process_btn = QPushButton("开始转换", clicked=self.start_text_processing)
        right_layout.addWidget(self.text_process_btn)
        _, self.text_result = self.create_scroll_textedit()
        right_layout.addWidget(QLabel("转换结果:"))
        right_layout.addWidget(self.text_result)

        column_layout.addWidget(left)
        column_layout.addWidget(right)
        layout.addWidget(columns)

        self.tab_widget.addTab(tab, "文本处理")

    def create_regex_gen_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("正则表达式生成", font=QFont("Arial", 20, QFont.Bold)))

        columns = QWidget()
        column_layout = QHBoxLayout(columns)

        # 左侧输入
        left = QWidget()
        left_layout = QVBoxLayout(left)
        _, self.regex_source = self.create_scroll_textedit("源文本...", False)
        left_layout.addWidget(QLabel("源文本:"))
        left_layout.addWidget(self.regex_source)
        _, self.regex_sample = self.create_scroll_textedit("样本格式...", False)
        left_layout.addWidget(QLabel("样本格式:"))
        left_layout.addWidget(self.regex_sample)

        # 右侧结果
        right = QWidget()
        right_layout = QVBoxLayout(right)
        self.regex_btn = QPushButton("生成正则表达式", clicked=self.start_regex_generation)
        right_layout.addWidget(self.regex_btn)
        _, self.regex_result = self.create_scroll_textedit()
        right_layout.addWidget(QLabel("生成结果:"))
        right_layout.addWidget(self.regex_result)

        column_layout.addWidget(left)
        column_layout.addWidget(right)
        layout.addWidget(columns)

        self.tab_widget.addTab(tab, "正则生成")
    def create_webshell_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("WebShell/内存马检测系统", font=QFont("Arial", 20, QFont.Bold)))

        _, self.webshell_input = self.create_scroll_textedit("粘贴文件内容或内存dump数据...", False)
        layout.addWidget(QLabel("输入待检测内容:"))
        layout.addWidget(self.webshell_input)

        self.webshell_btn = QPushButton("开始深度检测", clicked=self.start_webshell_analysis)
        layout.addWidget(self.webshell_btn)

        _, self.webshell_result = self.create_scroll_textedit()
        layout.addWidget(QLabel("检测结果:"))
        layout.addWidget(self.webshell_result)

        self.tab_widget.addTab(tab, "WebShell检测")
    def create_translation_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("AI多语言专业翻译", font=QFont("Arial", 20, QFont.Bold)))

        # 语言选择栏
        lang_control = QWidget()
        lang_layout = QHBoxLayout(lang_control)
        
        self.source_lang = QComboBox()
        self.source_lang.addItems(["自动检测", "中文", "英文", "日文", "韩文", "德文", "法文"])
        lang_layout.addWidget(QLabel("源语言:"))
        lang_layout.addWidget(self.source_lang)

        self.target_lang = QComboBox()
        self.target_lang.addItems(["中文", "英文", "日文", "韩文", "德文", "法文"])
        lang_layout.addWidget(QLabel("目标语言:"))
        lang_layout.addWidget(self.target_lang)

        layout.addWidget(lang_control)

        # 文本输入输出区域
        trans_columns = QWidget()
        trans_layout = QHBoxLayout(trans_columns)

        # 左侧输入
        _, self.trans_input = self.create_scroll_textedit("输入待翻译内容...", False)
        trans_layout.addWidget(QLabel("原文:"))
        trans_layout.addWidget(self.trans_input)

        # 右侧输出
        _, self.trans_output = self.create_scroll_textedit(read_only=True)
        trans_layout.addWidget(QLabel("译文:"))
        trans_layout.addWidget(self.trans_output)

        layout.addWidget(trans_columns)

        # 操作按钮
        self.trans_btn = QPushButton("开始翻译", clicked=self.start_translation)
        layout.addWidget(self.trans_btn)

        self.tab_widget.addTab(tab, "AI翻译")
    def start_webshell_analysis(self):
        content = self.webshell_input.toPlainText().strip()
        if not content:
            self.show_status("请输入检测内容", "red")
            return

        self.webshell_btn.setEnabled(False)
        self.webshell_result.setPlainText("深度分析中...")

        self.webshell_thread = WebShellAnalysisThread(content)
        self.webshell_thread.analysis_complete.connect(self.show_webshell_result)
        self.webshell_thread.start()
    def start_translation(self):
        text = self.trans_input.toPlainText().strip()
        if not text:
            self.show_status("请输入需要翻译的内容", "red")
            return

        source_lang = self.source_lang.currentText()
        target_lang = self.target_lang.currentText()

        self.trans_btn.setEnabled(False)
        self.trans_output.setPlainText("翻译中...")

        self.trans_thread = TranslationThread(text, source_lang, target_lang)
        self.trans_thread.translation_complete.connect(self.show_translation_result)
        self.trans_thread.start()
    def show_webshell_result(self, result, is_malicious):
        self.webshell_btn.setEnabled(True)
        bg_color = "#ff4757" if is_malicious else "#2ed573"
        border_color = "#e94560" if is_malicious else "#7bed9f"

        self.webshell_result.setStyleSheet(f"""
            QTextEdit {{
                background-color: {bg_color};
                color: white;
                border: 2px solid {border_color};
                border-radius: 5px;
                padding: 15px;
            }}
        """)
        self.webshell_result.setHtml(f"<pre>{result}</pre>")
        status = "发现恶意软件！" if is_malicious else "未发现恶意特征"
        self.show_status(status, "#e94560" if is_malicious else "#2ed573")
    def show_translation_result(self, result):
        self.trans_btn.setEnabled(True)
        self.trans_output.setPlainText(result)
        self.show_status("翻译完成", "#2ed573")
    def change_theme(self, theme_name):
        if theme_name in THEMES:
            theme = THEMES[theme_name]
            self.setStyleSheet(self.get_stylesheet(theme))

    def get_stylesheet(self, theme=None):
        if theme is None:
            theme = THEMES["深色主题"]
        return f"""
        QMainWindow, QWidget, QFrame {{
            background-color: {theme['main_bg']};
            color: {theme['text_color']};
            font-family: 'Menlo';
        }}
        QPushButton {{
            background-color: {theme['accent_color']};
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 500;
            min-width: 100px;
            margin: 4px;
        }}
        QPushButton:hover {{
            background-color: {theme['button_hover']};
        }}
        QPushButton:pressed {{
            background-color: {theme['button_pressed']};
        }}
        QTextEdit {{
            background-color: {theme['secondary_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            padding: 8px;
            font-family: Menlo, Consolas, monospace;
            font-size: 12px;
            line-height: 1.4;
        }}
        QLabel {{
            color: {theme['text_color']};
            padding: 4px;
            font-size: 13px;
            margin-bottom: 2px;
        }}
        QScrollArea {{
            background-color: transparent;
            border: none;
        }}
        QTabWidget::pane {{
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            background-color: {theme['secondary_bg']};
            top: -1px;
        }}
        QTabBar::tab {{
            background: {theme['main_bg']};
            color: {theme['text_color']};
            padding: 8px 16px;
            border: 1px solid {theme['border_color']};
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
            font-size: 12px;
        }}
        QTabBar::tab:selected {{
            background: {theme['secondary_bg']};
            border-bottom: 2px solid {theme['accent_color']};
        }}
        QTabBar::tab:hover {{
            background-color: {theme['button_hover']};
        }}
        QComboBox {{
            background-color: {theme['secondary_bg']};
            color: {theme['text_color']};
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            padding: 4px 8px;
            min-width: 120px;
        }}
        QComboBox:hover {{
            border-color: {theme['accent_color']};
        }}
        QComboBox::drop-down {{
            border: none;
            width: 16px;
        }}
        QComboBox::down-arrow {{
            width: 0;
            height: 0;
            border-left: 6px solid transparent;
            border-right: 6px solid transparent;
            border-top: 6px solid {theme['text_color']};
            margin-top: 2px;
            margin-right: 4px;
        }}
        QProgressBar {{
            border: 1px solid {theme['border_color']};
            border-radius: 4px;
            background-color: {theme['main_bg']};
            text-align: center;
            height: 16px;
            margin: 8px 0;
        }}
        QProgressBar::chunk {{
            background-color: {theme['accent_color']};
            border-radius: 3px;
        }}
        """

    def start_traffic_analysis(self):
        http_data = self.traffic_input.toPlainText().strip()
        if not http_data:
            self.show_status("请输入有效的HTTP请求数据", "red")
            return

        self.analyze_btn.setEnabled(False)
        self.traffic_result.setPlainText("分析中...")

        self.analysis_thread = AnalysisThread(http_data)
        self.analysis_thread.analysis_complete.connect(self.show_traffic_result)
        self.analysis_thread.start()

    def show_traffic_result(self, result, is_attack):
        self.analyze_btn.setEnabled(True)
        bg_color = "#ff4757" if is_attack else "#2ed573"
        border_color = "#e94560" if is_attack else "#7bed9f"

        self.traffic_result.setStyleSheet(f"""
            QTextEdit {{
                background-color: {bg_color};
                color: white;
                border: 2px solid {border_color};
                border-radius: 5px;
                padding: 15px;
            }}
        """)
        self.traffic_result.setHtml(f"<pre>{result}</pre>")
        status = "检测到恶意流量！" if is_attack else "流量正常"
        self.show_status(status, "#e94560" if is_attack else "#2ed573")

    def start_decoding(self):
        text = self.decode_input.toPlainText().strip()
        if not text:
            self.show_status("请输入需要解码的内容", "red")
            return

        self.decode_btn.setEnabled(False)
        self.decode_result.setPlainText("解码中...")

        self.decoding_thread = DecodingThread(text)
        self.decoding_thread.decoding_complete.connect(self.show_decoding_result)
        self.decoding_thread.start()

    def show_decoding_result(self, result):
        self.decode_btn.setEnabled(True)
        self.decode_result.setPlainText(result)
        self.show_status("解码完成", "#2ed573")

    def start_js_audit(self):
        js_code = self.js_input.toPlainText().strip()
        if not js_code:
            self.show_status("请输入JavaScript代码", "red")
            return

        self.js_audit_btn.setEnabled(False)
        self.js_result.setPlainText("审计中...")

        self.js_audit_thread = JsAuditThread(js_code)
        self.js_audit_thread.audit_complete.connect(self.show_js_audit_result)
        self.js_audit_thread.start()

    def show_js_audit_result(self, result):
        self.js_audit_btn.setEnabled(True)
        self.js_result.setPlainText(result)
        self.show_status("代码审计完成", "#2ed573")

    def start_process_analysis(self):
        process_data = self.process_input.toPlainText().strip()
        if not process_data:
            self.show_status("请输入进程信息", "red")
            return

        self.process_btn.setEnabled(False)
        self.process_result.setPlainText("分析中...")

        self.process_thread = ProcessAnalysisThread(process_data)
        self.process_thread.process_complete.connect(self.show_process_result)
        self.process_thread.start()

    def show_process_result(self, result):
        self.process_btn.setEnabled(True)
        self.process_result.setPlainText(result)
        self.show_status("进程分析完成", "#2ed573")

    def start_http_conversion(self):
        http_request = self.http_input.toPlainText().strip()
        if not http_request:
            self.show_status("请输入HTTP请求", "red")
            return

        self.convert_btn.setEnabled(False)
        self.conversion_result.setPlainText("转换中...")

        self.http_thread = HttpToPythonThread(http_request)
        self.http_thread.conversion_complete.connect(self.show_conversion_result)
        self.http_thread.start()

    def show_conversion_result(self, result):
        self.convert_btn.setEnabled(True)
        self.conversion_result.setPlainText(result)
        self.show_status("转换完成", "#2ed573")

    def start_text_processing(self):
        source_text = self.text_source.toPlainText().strip()
        sample_text = self.text_sample.toPlainText().strip()
        if not source_text or not sample_text:
            self.show_status("请输入源文本和样本格式", "red")
            return

        self.text_process_btn.setEnabled(False)
        self.text_result.setPlainText("处理中...")

        self.text_thread = TextProcessThread(source_text, sample_text)
        self.text_thread.process_complete.connect(self.show_text_result)
        self.text_thread.start()

    def show_text_result(self, result):
        self.text_process_btn.setEnabled(True)
        self.text_result.setPlainText(result)
        self.show_status("文本处理完成", "#2ed573")

    def start_regex_generation(self):
        source_text = self.regex_source.toPlainText().strip()
        sample_text = self.regex_sample.toPlainText().strip()
        if not source_text or not sample_text:
            self.show_status("请输入源文本和样本格式", "red")
            return

        self.regex_btn.setEnabled(False)
        self.regex_result.setPlainText("生成中...")

        self.regex_thread = RegexGenThread(source_text, sample_text)
        self.regex_thread.regex_complete.connect(self.show_regex_result)
        self.regex_thread.start()

    def show_regex_result(self, result):
        self.regex_btn.setEnabled(True)
        self.regex_result.setPlainText(result)
        self.show_status("正则表达式生成完成", "#2ed573")

    def show_status(self, message, color):
        self.statusBar().showMessage(message)
        self.statusBar().setStyleSheet(f"color: {color}; font-weight: bold;")
    def create_source_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("源码安全审计系统", font=QFont("Arial", 20, QFont.Bold)))

        # 文件夹选择区域
        file_control = QWidget()
        file_layout = QHBoxLayout(file_control)
        self.btn_choose_dir = QPushButton("选择源码目录", clicked=self.choose_directory)
        self.label_dir = QLabel("未选择目录")
        file_layout.addWidget(self.btn_choose_dir)
        file_layout.addWidget(self.label_dir)
        layout.addWidget(file_control)

        # 文件类型过滤
        filter_control = QWidget()
        filter_layout = QHBoxLayout(filter_control)
        self.check_php = QCheckBox("PHP")
        self.check_jsp = QCheckBox("JSP")
        self.check_asp = QCheckBox("ASP")
        self.check_php.setChecked(True)
        self.check_jsp.setChecked(True)
        self.check_asp.setChecked(True)
        filter_layout.addWidget(QLabel("文件类型过滤:"))
        filter_layout.addWidget(self.check_php)
        filter_layout.addWidget(self.check_jsp)
        filter_layout.addWidget(self.check_asp)
        layout.addWidget(filter_control)

        # 进度条
        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        # 操作按钮
        self.btn_audit = QPushButton("开始深度审计", clicked=self.start_source_audit)
        layout.addWidget(self.btn_audit)

        # 结果显示
        _, self.audit_result = self.create_scroll_textedit()
        layout.addWidget(QLabel("审计结果:"))
        layout.addWidget(self.audit_result)

        self.tab_widget.addTab(tab, "源码审计")

    def choose_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "选择源码目录")
        if directory:
            self.label_dir.setText(directory)
            self.scan_files(directory)

    def scan_files(self, directory):
        exts = []
        if self.check_php.isChecked(): exts.append('*.php')
        if self.check_jsp.isChecked(): exts.append('*.jsp')
        if self.check_asp.isChecked(): exts.append('*.asp')

        self.audit_files = []
        for ext in exts:
            self.audit_files.extend(glob.glob(os.path.join(directory, '**', ext), recursive=True))

        self.label_dir.setText(f"已选择目录: {directory} ({len(self.audit_files)}个文件)")

    def start_source_audit(self):
        if not self.audit_files:
            self.show_status("请先选择源码目录", "red")
            return

        self.btn_audit.setEnabled(False)
        self.audit_result.setPlainText("开始审计...")

        self.audit_thread = SourceCodeAuditThread(self.audit_files, self)  # 添加 self 作为 parent
        self.audit_thread.audit_complete.connect(self.show_audit_result)
        self.audit_thread.progress_updated.connect(self.progress.setValue)
        self.audit_thread.start()

    def show_audit_result(self, result):
        self.btn_audit.setEnabled(True)
        result=result.replace('\n', '<br>').replace(' ', '&nbsp;')
        self.audit_result.setHtml(f"""
        <html>
        <body style="font-family: 'Microsoft Yahei'; color: #333;">
            <div style="padding: 20px; background: #f8f9fa; border-radius: 5px;">
                {result}
            </div>
        </body>
        </html>
        """)
        self.show_status("源码审计完成", "#2ed573")

if __name__ == '__main__':
    if os.name == 'nt':
        print("当前系统是 Windows")
        sys.argv += ['-platform', 'windows']

    elif os.name == 'posix':
        print("当前系统是 macOS")
        sys.argv += ['-platform', 'cocoa']
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    palette = app.palette()
    gradient = QLinearGradient(0, 0, 0, 400)
    gradient.setColorAt(0, QColor(22, 33, 62))
    gradient.setColorAt(1, QColor(26, 26, 46))
    palette.setBrush(QPalette.Window, gradient)
    app.setPalette(palette)
    
    window = CyberSecurityApp()
    window.show()
    sys.exit(app.exec_())