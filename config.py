# API配置
API_TYPE="qwen"  # Supported values: "deepseek", "qwen", "openai", "ollama"

# DeepSeek API配置
DEEPSEEK_API_KEY=""

# OPENAI
OPENAI_API_KEY=""

# QWEN
QWEN_API_KEY=""

# OLLAMA
OLLAMA_API_KEY=""
OLLAMA_API_URL="http://localhost:11434/v1"  # Ollama API地址


## 可选参数

## OPENAI 第三方API地址
# OPENAI_API_URL="https://api.openai.com/v1/"

## MODEL
# DEEPSEEK_MODEL=""
# QWEN_MODEL=""
# OPENAI_MODEL=""
# OLLAMA_MODEL=""


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