# Donut Web - Shellcode 转换和加载器生成工具

一个基于 Go 语言和 [Donut](https://github.com/TheWover/donut) 项目的 Web 界面工具，用于将 .NET 程序集、PE 文件等转换为 shellcode，并生成多种编程语言的加载器。
# v1.2功能
1.修复部分编码乱码问题
2.增强生成异常处理
3.生成的所有文件均在dount web目录中均可查看
4.关于加载器的问题，需要自己来编译，示例中可能还存在一些问题
5.本框架只是演示框架，当然可生成相关的shellcode编码
6.你可正常使用本框架生成shellcode
7.还存在一些问题，你可以进行提交或你自行处理你的功能逻辑以及一些其他功能的优化
8.可以更好fork该项目用于你自身产环境 
8.本工具完全开源！
## 功能特性

### Shellcode 转换功能
- 支持将 .NET 程序集、PE 文件、脚本文件转换为 shellcode
- 支持多种目标架构：x86、x64、x84 (AMD64+x86)
- 支持多种输出格式：C 语言数组、Ruby 数组、Python 数组、PowerShell 字符串、Base64 字符串、C# 数组、十六进制字符串、UUID 字符串
- 提供多种压缩选项：无压缩、aPLib、LZNT1、Xpress、Xpress Huffman
- 支持 AMSI 和 ETW 绕过
- 支持自定义模块名称、入口点和参数

### 加载器生成功能
- 支持直接输入十六进制或 Base64 格式的 shellcode
- 支持上传 shellcode 文件
- 支持生成多种编程语言的加载器：C 语言、Go 语言、Rust 语言、Python
- 提供代码复制和文件下载功能

## 技术栈

- **后端**：Go 语言 + Gin Web 框架
- **前端**：HTML5 + Tailwind CSS v3 + Font Awesome
- **核心引擎**：[Donut](https://github.com/TheWover/donut)

## 安装和使用

### 1. 克隆项目

```bash
git clone https://github.com/yourusername/donut-web.git
cd donut-web
```

### 2. 安装依赖

确保你已经安装了 Go 1.20 或更高版本，然后运行：

```bash
go mod download
```

### 3. 准备 Donut 可执行文件

1. 从 [Donut GitHub 仓库](https://github.com/TheWover/donut) 下载预编译的 donut.exe 文件
2. 在项目根目录创建 `donut` 文件夹
3. 将 donut.exe 放入该文件夹中

### 4. 运行项目

```bash
go run main.go
```

默认情况下，服务将在 `http://localhost:8080` 启动。

## 项目结构

```
donut-web/
├── main.go          # 主程序入口
├── go.mod           # Go 模块定义
├── donut/           # 存放 donut.exe
├── static/          # 静态资源文件
│   └── index.html   # Web 界面
└── temp/            # 临时文件目录（自动创建）
```

## 使用说明

### Shellcode 转换
1. 点击「浏览」按钮上传你要转换的文件（.NET 程序集、PE 文件等）
2. 选择目标架构、输出格式和其他选项
3. 点击「转换为 Shellcode」按钮
4. 转换完成后，你可以复制生成的 shellcode 或下载文件

### 加载器生成
1. 选择 shellcode 输入方式（十六进制、Base64 或文件）
2. 提供 shellcode 内容或上传文件
3. 选择输出语言（C、Go、Rust 或 Python）
4. 点击「生成加载器」按钮
5. 生成完成后，你可以复制生成的代码或下载文件

## 注意事项

1. 本工具仅供学习和研究使用，请遵守相关法律法规
2. 确保你的系统已安装必要的依赖库，特别是生成 C、Rust 等加载器时
3. 大文件转换可能需要较长时间，请耐心等待
4. 转换后的 shellcode 和生成的加载器可能会被安全软件检测为恶意代码

## 许可证

本项目基于 MIT 许可证开源。

## 致谢

- 感谢 [Donut](https://github.com/TheWover/donut) 项目提供的核心功能
- 感谢 Tailwind CSS 和 Gin Web 框架提供的技术支持