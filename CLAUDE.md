# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 如何开发和测试

```bash
# 直接双击或用浏览器打开
start index.html
```

项目是纯静态文件，无构建工具、无框架、无服务器。改完代码刷新浏览器即可看到效果。

## 架构

```
index.html      → 页面结构（锁屏遮罩 + 弹窗 + 工具栏 + 表格 + 表单 + 生成器面板）
css/style.css   → 全部样式，CSS 变量集中在 :root
js/app.js       → 全部逻辑，单文件约 550 行，按功能分段
```

## 关键设计决策

- **加密方案**：浏览器原生 Web Crypto API（AES-256-GCM + PBKDF2 密钥派生），不用 CryptoJS CDN，因为国内网络可能无法访问 CDN
- **数据持久化**：localStorage，键名 `pw_manager_data`（密码条目 JSON）、`pw_master_hash`（主密码 SHA-256 哈希）
- **.enc 文件格式**：Salt(16字节) + IV(12字节) + 密文，Base64 编码后写入文件
- **用户群体**：国内用户，界面中文，无编程基础的普通用户

## js/app.js 代码分段

| 行号区域 | 模块 | 说明 |
|---------|------|------|
| 1-4 | 全局状态 | `entries` 数组、`failCount`、`lockUntil` |
| 6-165 | 主密码锁 | `hashPw`、`initLock`、`doUnlock`/`doSetup`、定时锁定 |
| 167-197 | 修改主密码 | 模态弹窗和验证逻辑 |
| 199-211 | 持久化 | `load()`/`save()`，注意 save 没有 try-catch |
| 213-284 | TXT 解析 | `parseLine()` 逐格式判断，`handleFile()` 读文件 |
| 286-328 | 表格渲染 | `render()` 搜索过滤 + 动态生成 HTML |
| 330-385 | 工具函数 | HTML 转义、剪贴板复制、Toast 提示、删除条目 |
| 387-436 | 密码生成器 | `crypto.getRandomValues` 安全随机 |
| 438-497 | 多选 + AES | 复选框全选、PBKDF2 密钥派生、加解密、导出导入 |
| 499-538 | 事件绑定 | DOMContentLoaded 中统一绑定 |

## 功能修改入口

- 改 TXT 解析 → `parseLine()` 加 `else if` 分支
- 改加密参数（迭代次数、密钥长度）→ `encryptData()`/`decryptData()` 中的 PBKDF2 和 AES-GCM 配置
- 改主密码锁定规则 → `doUnlock()` 中的错误次数判断
- 添加/修改表格列 → 同时改 HTML `<thead>`、CSS 列宽、JS `render()` 模板

## 用户偏好

- 用户没有编程基础，功能完成后需要用通俗语言解释代码
- 回复简洁，先确认方案再动手
- 每步做完开浏览器测试验证
