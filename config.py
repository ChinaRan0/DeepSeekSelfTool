# API配置
API_TYPE="deepseek"  # 可选值: "deepseek" 或 "ollama"

# DeepSeek API配置
# 官方默认API地址: "https://api.deepseek.com/v1/chat/completions"
# 硅基流动：https://api.siliconflow.cn/v1/chat/completions
DEEPSEEK_API_URL=""

DEEPSEEK_API_KEY=""

# DeepSeek模型名称，官方默认模型: "deepseek-chat"
# 硅基流动：deepseek-ai/DeepSeek-V3
DEEPSEEK_MODEL=""

# Ollama API配置
OLLAMA_API_URL="http://localhost:11434/api/chat"  # Ollama API地址
OLLAMA_MODEL="qwen2.5-coder:14b"  # Ollama模型名称

# 主题配色方案
THEMES = {
    "深色主题": {
        "main_bg": "#1e1e1e",
        "secondary_bg": "#2d2d2d",
        "text_color": "#ffffff",
        "accent_color": "#007acc",
        "border_color": "#404040",
        "button_hover": "#005999",
        "button_pressed": "#004c80"
    },
    "浅色主题": {
        "main_bg": "#f5f5f5",
        "secondary_bg": "#ffffff",
        "text_color": "#333333",
        "accent_color": "#2196f3",
        "border_color": "#e0e0e0",
        "button_hover": "#1976d2",
        "button_pressed": "#1565c0"
    }
}
