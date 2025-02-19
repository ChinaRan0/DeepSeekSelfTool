# [DeepSeekSelfTool](https://github.com/ChinaRan0/DeepSeekSelfTool)

首个由DeepSeek独立开发的AI网络安全工具箱

首发公众号 **知攻善防实验室**

## 目前功能

流量分析、JS代码审计、进程分析、HTTP转python、文本处理、正则表达式生成、WebShell检测、翻译、代码审计



## bilibili

https://www.bilibili.com/video/BV1yxNAenEwj/

https://www.bilibili.com/video/BV1skNoeuEZu/

### 流量分析

调用的API接口，让AI分析流量。

意旨，粘贴数据包，让AI判断是否为恶意流量，方便安服、护网蓝队使用

### 模型推荐

线上 api 模型推荐 DeepSeekV3 （不要使用 R1 推理模型，会有多余的输出且非常慢。）

本地模型推荐使用 qwen2.5-coder:14b

恶意流量

![](./assets/image-20250210204613367.png)

正常流量

![](./assets/image-20250210204511164.png)

在流量分析中，经常需要解码以及日常需要解码的需求，可以直接加一个AI只能解码

![](./assets/image-20250210204719077.png)

### JS代码审计

直接将关键的JavaScript代码粘贴进来，AI自动输出问题和风险点

![](./assets/image-20250210204957732.png)

### 进程分析

粘贴Windows的tasklist或者Linux/macOS的ps aux，以显示所有进程，然后直接粘贴进来让AI去分析

可以用于

红队：杀软识别

蓝队：应急响应进程分析

![](./assets/image-20250210203856225.png)

会把进程分为三类，可疑进程、杀软进程、第三方软件进程，并总结给你建议。

### HTTP转Python

有时候我们想写POC/EXP的时候，很多重复性的代码需要去写，这里不用了，直接把HTTP请求包粘贴进去，AI几秒钟就生成完成了

![](./assets/image-20250210204543714.png)

### 文本处理

有时候在处理一些文本的时候，例如资产测绘平台导出的数据要交给另外一个工具去调用，但是另外一个工具需要制定的格式，那么我们就可以输入少量的源文本和少量的样本格式，让AI写脚本，把源文本转换成样本格式

例如：

![](./assets/image-20250210204552857.png)

### 正则表达式生成

平时开发中最头疼的正则表达式，也是输入源文本和样本格式，AI直接给你正则表达式

例如在网页爬虫中

![](./assets/image-20250210204600326.png)

我输入源文本，这个文本可以是任何文本，我这里用的是HTML，然后我想匹配样本格式，AI就会给我很多正则表达式供我参考



### WebShell检测

AI检测WebShell的能力可太强了，强的可怕

他可以检测WebShell和内存马，Webshell直接给文件粘贴进去，内存马需要你人工dump出来。

恶意文件

这是以前文章一个大佬写的“原神免杀WebShell”的检测结果

![](./assets/image-20250210205106905.png)

正常文件

![](./assets/image-20250210205203960.png)

### AI翻译

以SQLmap为例子

![](./assets/image-20250210205523064.png)

效果自己看，嘻嘻。



我随机抽取了几个php文件做测试，结果还挺好的，都审出来了。但是由于上下文的原因，不能夸文件进行审计，原理是逐个逐个将文件吐给AI，单丝对于我这种不会代码审计的，已经足够爽了。

![](./assets/image-20250210205353354.png)



## 漏洞分析

写报告用的，由于平时写报告需要网上各种搜索复制粘贴，所以弄的这个。（自动化写报告）

![image-20250210205647266](./assets/image-20250210205647266.png)





### 使用教程 

```python
git clone https://github.com/ChinaRan0/DeepSeekSelfTool
cd DeepSeekSelfTool
pip install -r requirements.txt
配置config.py
python DeepSeekSelfTool.py
```

## config配置教程

```python
# API配置
API_TYPE="deepseek"  # 可选值: "deepseek" 或 "ollama"[二选一]

# DeepSeek API配置
# 官方默认API地址: "https://api.deepseek.com/v1/chat/completions"
# 硅基流动：https://api.siliconflow.cn/v1/chat/completions
DEEPSEEK_API_URL=""  # 这里填写API地址

DEEPSEEK_API_KEY=""  # 这里填写API-key

# DeepSeek模型名称，官方默认模型: "deepseek-chat"
# 硅基流动：deepseek-ai/DeepSeek-V3
DEEPSEEK_MODEL=""		# 这里填写模型



# Ollama API配置
OLLAMA_API_URL="http://localhost:11434/api/chat"  # Ollama API地址
OLLAMA_MODEL="qwen2.5-coder:14b"  # Ollama模型名称






```
## 运行环境

支持Windows+MacOS+Linux
注意，Linux需要讲DeepSeekSelfTool.py的
```python
    if os.name == 'nt':
        print("当前系统是 Windows")
        sys.argv += ['-platform', 'windows']

    elif os.name == 'posix':
        print("当前系统是 macOS")
        sys.argv += ['-platform', 'cocoa']
```
删除






## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ChinaRan0/DeepSeekSelfTool&type=Date)](https://star-history.com/#ChinaRan0/DeepSeekSelfTool&Date)





