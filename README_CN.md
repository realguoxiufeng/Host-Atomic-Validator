# Host Atomic Validator

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![MITRE ATT&CK](https://img.shields.io/badge/ATT%26CK-67%20Techniques-blue)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()

主机安全验证工具，用于执行 MITRE ATT&CK 原子测试。本项目提供批量执行攻击模拟测试和自动生成报告的能力，支持 Windows 和 Linux 平台。

[English](README.md) | 中文文档

## 功能特性

- **跨平台支持**：Windows 和 Linux 双平台实现
- **批量执行**：批量运行多个原子测试
- **分类测试**：按 MITRE ATT&CK 战术分类执行测试
- **自动报告**：生成 HTML、Excel、Word 和文本格式报告
- **风险评估**：内置技术风险等级分类
- **进度追踪**：详细的日志记录和执行摘要

## 支持的 MITRE ATT&CK 战术

| 类别 | 说明 | 示例技术 |
|------|------|----------|
| 执行 | 执行恶意代码 | T1059, T1064, T1204, T1569 |
| 持久化 | 保持系统访问 | T1136, T1547, T1053, T1543 |
| 权限提升 | 获取更高权限 | T1548, T1068, T1134, T1055 |
| 防御规避 | 避免被检测 | T1027, T1112, T1070, T1036 |
| 发现 | 探测环境信息 | T1083, T1018, T1057, T1518 |
| 横向移动 | 网络中移动 | T1021, T1077, T1091, T1550 |
| 凭据访问 | 窃取凭据 | T1003, T1552, T1555 |
| 命令与控制 | 建立控制通道 | T1071, T1095, T1132 |

## 系统要求

### Windows
- Windows Server 2016/2019/2022 或 Windows 10/11
- PowerShell 5.0 或更高版本
- `goart-windows.exe`（必需的执行器）

### Linux
- Linux 操作系统
- Bash 4.0+
- `goart-linux`（必需的执行器）

### Python（用于报告生成）
- Python 3.6+
- 依赖：pandas, openpyxl, python-docx

## 安装部署

```bash
# 克隆仓库
git clone https://github.com/realguoxiufeng/Host-Atomic-Validator.git
cd Host-Atomic-Validator

# 安装 Python 依赖
pip install -r basforwindows/requirements.txt
# 或 Linux
pip install -r basforlinux/requirements.txt
```

### 执行器配置

`goart-windows.exe` 和 `goart-linux` 执行器是必需的，但由于 GitHub 文件大小限制未包含在本仓库中。请将这些二进制文件放置在对应目录：
- Windows: `basforwindows/goart-windows.exe`
- Linux: `basforlinux/goart-linux`

## 快速开始

### Windows

```powershell
# 进入 Windows 目录
cd basforwindows

# 设置执行策略（如需要）
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 运行所有测试
.\run_all_atomics.ps1

# 运行特定技术
.\run_all_atomics.ps1 -t T1059

# 按类别运行
.\run_all_atomics.ps1 -c execution

# 干运行模式（预览不执行）
.\run_all_atomics.ps1 -DryRun
```

### Linux

```bash
# 进入 Linux 目录
cd basforlinux

# 设置执行权限
chmod +x run_all_atomics.sh goart-linux

# 运行所有测试
sudo ./run_all_atomics.sh

# 运行特定技术
sudo ./run_all_atomics.sh -t T1059

# 按类别运行
sudo ./run_all_atomics.sh -c execution
```

### 生成报告

```bash
# 生成所有格式报告
python analyze_atomic_logs2.py

# 生成特定格式
python analyze_atomic_logs2.py --format html
python analyze_atomic_logs2.py --format excel
python analyze_atomic_logs2.py --format docx
```

## 项目结构

```
Host-Atomic-Validator/
├── basforwindows/           # Windows 实现
│   ├── run_all_atomics.ps1  # 主 PowerShell 脚本
│   ├── analyze_atomic_logs2.py  # 报告生成器
│   ├── TTPs.md              # 支持的技术列表
│   ├── configs/             # 配置文件
│   ├── logs/                # 测试日志（自动创建）
│   └── reports/             # 生成的报告（自动创建）
├── basforlinux/             # Linux 实现
│   ├── run_all_atomics.sh   # 主 Bash 脚本
│   ├── analyze_atomic_logs2.py  # 报告生成器
│   ├── TTPs.md              # 支持的技术列表
│   ├── configs/             # 配置文件
│   ├── logs/                # 测试日志（自动创建）
│   └── reports/             # 生成的报告（自动创建）
├── CLAUDE.md                # Claude Code 指导文件
├── LICENSE                  # MIT 许可证
└── README.md                # 本文件
```

## 命令行选项

### Windows (PowerShell)

| 参数 | 别名 | 说明 |
|------|------|------|
| `-Help` | `-h` | 显示帮助信息 |
| `-TechniqueId` | `-t` | 运行特定技术测试 |
| `-Category` | `-c` | 按类别运行测试 |
| `-ListFile` | `-l` | 从文件读取技术列表 |
| `-SkipFailed` | `-s` | 跳过失败的测试继续执行 |
| `-DryRun` | `-d` | 显示测试但不执行 |
| `-Verbose` | `-v` | 显示详细输出 |
| `-Timeout` | - | 测试超时时间（秒，默认：300） |

### Linux (Bash)

| 选项 | 说明 |
|------|------|
| `-h, --help` | 显示帮助信息 |
| `-t TECHNIQUE_ID` | 运行特定技术测试 |
| `-c CATEGORY` | 按类别运行测试 |
| `-l LIST_FILE` | 从文件读取技术列表 |
| `-s, --skip-failed` | 跳过失败的测试继续执行 |
| `-d, --dry-run` | 显示测试但不执行 |
| `-v, --verbose` | 显示详细输出 |
| `--timeout SEC` | 测试超时时间（秒，默认：300） |

## 报告格式

`analyze_atomic_logs2.py` 脚本可生成多种格式的报告：

| 格式 | 说明 |
|------|------|
| HTML | 带图表和统计的交互式报告 |
| Excel | 多工作表的详细分析报告 |
| Word | 专业格式的正式报告 |
| Text | 纯文本格式便于快速查看 |

## 安全警告

**本工具执行真实的攻击模拟测试。请务必阅读并理解以下内容：**

1. **隔离环境**：仅在隔离的专用测试环境中运行测试
2. **系统影响**：测试可能修改系统状态、创建文件或更改配置
3. **授权要求**：确保测试前已获得适当授权
4. **数据保护**：保护日志和报告中的敏感信息
5. **禁止生产环境**：请勿在生产环境中运行

## 参与贡献

欢迎贡献！请随时提交 Pull Request。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详情请查看 [LICENSE](LICENSE) 文件。

## 致谢

- [MITRE ATT&CK Framework](https://attack.mitre.org/) - 对手战术、技术和程序
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - 原子测试库
- [Red Canary](https://redcanary.com/) - Atomic Red Team 维护者

## 相关资源

- [MITRE ATT&CK 官网](https://attack.mitre.org/)
- [Atomic Red Team 项目](https://github.com/redcanaryco/atomic-red-team)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## 免责声明

本工具仅供教育和授权安全测试目的使用。作者和贡献者不对本工具的任何误用或造成的损害负责。用户有责任确保在进行任何安全测试之前获得适当的授权。请始终遵守您所在司法管辖区的适用法律和法规。