# MITRE ATT&CK 批量测试脚本使用手册

## 概述

`run_all_atomics.sh` 是一个用于批量执行 MITRE ATT&CK 原子测试(Atomic Red Team)的 Bash 脚本。该脚本通过 goart-linux 工具执行安全测试，并自动记录日志和生成报告。

## 系统要求

- Linux 操作系统
- Bash 4.0+
- goart-linux 可执行文件
- Atomic Red Team 项目（可选，用于本地技术定义）

## 目录结构

```
/opt/bas/
├── goart-linux          # goart 执行程序
├── logs/                 # 测试日志输出目录
├── reports/              # 测试报告输出目录
├── configs/              # 配置文件目录
└── run_all_atomics.sh    # 本脚本

/opt/atomic-red-team/     # Atomic Red Team 项目目录（可选）
└── atomics/              # 技术定义目录
```

## 基本用法

```bash
./run_all_atomics.sh [选项]
```

## 命令行选项

| 选项 | 参数 | 说明 |
|------|------|------|
| `-h, --help` | 无 | 显示帮助信息 |
| `-t` | TECHNIQUE_ID | 运行特定技术ID的测试 |
| `-c` | CATEGORY | 按类别运行测试 |
| `-l` | LIST_FILE | 从文件读取技术列表 |
| `-s, --skip-failed` | 无 | 跳过失败的测试继续运行 |
| `-d, --dry-run` | 无 | 只显示将要运行的测试，不实际执行 |
| `-v, --verbose` | 无 | 显示详细信息 |
| `--max-parallel` | N | 最大并行进程数（默认: 1） |
| `--timeout` | SEC | 单个测试超时时间（默认: 300秒） |
| `--index` | INDEX | 指定测试索引 |

## 使用示例

### 1. 运行所有测试

```bash
./run_all_atomics.sh
```

执行前会显示技术列表并要求确认。

### 2. 运行特定技术测试

```bash
# 运行 T1059 技术测试
./run_all_atomics.sh -t T1059

# 支持完整格式
./run_all_atomics.sh -t 'T1021.004 - Remote Services: SSH'
```

### 3. 按类别运行测试

```bash
# 运行执行类别测试
./run_all_atomics.sh -c execution
```

支持的类别：
- `execution` - 执行
- `persistence` - 持久化
- `privilege-escalation` - 权限提升
- `defense-evasion` - 防御规避
- `discovery` - 发现
- `lateral-movement` - 横向移动
- `collection` - 数据收集
- `exfiltration` - 数据外泄
- `command-and-control` - 命令与控制

### 4. 从配置文件运行

```bash
# 从文件读取测试列表
./run_all_atomics.sh -l techniques.txt

# 显示详细信息
./run_all_atomics.sh -l techniques.txt -v
```

### 5. 干运行模式（预览）

```bash
# 只显示将要运行的测试，不实际执行
./run_all_atomics.sh -d
```

### 6. 跳过失败继续执行

```bash
# 即使某些测试失败也继续执行后续测试
./run_all_atomics.sh -l techniques.txt -s
```

### 7. 自定义超时时间

```bash
# 设置单个测试超时为 600 秒
./run_all_atomics.sh -t T1059 --timeout 600
```

## 配置文件格式

配置文件支持多种格式，每行一个技术：

```
# 注释行会被跳过

# 基本格式
T1021.004

# 带描述格式
T1021.004 - Remote Services: SSH

# 空格分隔格式
T1021.004 Remote Services: SSH

# 逗号分隔格式
T1021.004,Remote Services: SSH
```

## 输出文件

### 日志文件

位置: `/opt/bas/logs/`

格式: `{技术ID}_{时间戳}.log`

示例: `T1059_20260318_143025.log`

### 测试汇总

位置: `/opt/bas/reports/`

格式: `test_summary_{时间戳}.txt`

### YAML 报告

格式: `{技术ID}_{时间戳}.yaml`

## 执行流程

1. **检查依赖** - 验证 goart-linux 是否存在
2. **解析参数** - 处理命令行选项
3. **获取技术列表** - 从参数、文件或默认列表获取
4. **显示预览** - 列出将要测试的技术
5. **确认执行** - 要求用户确认
6. **批量执行** - 依次执行测试
7. **生成报告** - 输出测试汇总

## 环境变量配置

可在脚本开头修改以下配置：

```bash
BASE_DIR="/opt/bas"           # 基础目录
GOART_PATH="${BASE_DIR}/goart-linux"  # goart 路径
LOG_DIR="${BASE_DIR}/logs"    # 日志目录
REPORT_DIR="${BASE_DIR}/reports"      # 报告目录
ATOMICS_PATH="/opt/atomic-red-team"   # Atomic Red Team 路径
```

## 常见问题

### Q: goart-linux 未找到

**解决方法**:
```bash
# 检查文件是否存在
ls -la /opt/bas/goart-linux

# 添加执行权限
chmod +x /opt/bas/goart-linux
```

### Q: Atomic Red Team 项目不存在

**解决方法**:
```bash
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team
```

### Q: jq 未安装警告

jq 是可选依赖，如需安装：
```bash
# CentOS/RHEL
yum install jq

# Ubuntu/Debian
apt-get install jq
```

### Q: 测试超时

默认超时为 300 秒，可通过 `--timeout` 参数调整：
```bash
./run_all_atomics.sh --timeout 600
```

## 注意事项

1. **权限要求**: 确保脚本有足够的权限执行测试操作
2. **系统影响**: 某些原子测试可能对系统产生影响，建议在测试环境中运行
3. **日志管理**: 定期清理 `/opt/bas/logs/` 目录中的旧日志文件
4. **并行执行**: 当前版本并行执行功能有限，建议使用默认值

## 相关脚本

- `analyze_atomic_logs2.py` - 日志分析脚本，用于生成安全验证报告

## 版本历史

- v1.0 - 初始版本，支持基本批量测试功能