# MITRE ATT&CK 测试日志分析工具使用手册

## 概述

`analyze_atomic_logs2.py` 是一个用于分析 MITRE ATT&CK 原子测试日志的 Python 工具。该脚本自动解析 goart 生成的日志文件，生成专业的安全验证报告。

## 系统要求

- Python 3.6+
- 必需依赖：
  - pandas
- 可选依赖：
  - python-docx（生成 Word 报告）

## 安装依赖

```bash
# 安装必需依赖
pip install pandas

# 安装可选依赖（用于生成 Word 报告）
pip install python-docx

# 安装所有依赖
pip install pandas python-docx openpyxl
```

## 基本用法

```bash
python3 analyze_atomic_logs2.py [选项]
```

## 命令行选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--log-dir` | `/opt/bas/logs` | 日志目录路径 |
| `--report-dir` | `/opt/bas/reports` | 报告输出目录 |
| `--format` | `all` | 报告格式: html, excel, text, docx, all |
| `--output` | 自动生成 | 指定输出文件名（不含扩展名） |

## 使用示例

### 1. 生成所有格式报告

```bash
python3 analyze_atomic_logs2.py
```

默认输出：
- `security_validation_report_{时间戳}.html`
- `security_validation_report_{时间戳}.xlsx`
- `security_validation_report_{时间戳}.txt`
- `security_validation_report_{时间戳}.docx`

### 2. 指定日志和报告目录

```bash
python3 analyze_atomic_logs2.py --log-dir /path/to/logs --report-dir /path/to/reports
```

### 3. 生成特定格式报告

```bash
# 仅生成 HTML 报告
python3 analyze_atomic_logs2.py --format html

# 仅生成 Excel 报告
python3 analyze_atomic_logs2.py --format excel

# 仅生成文本报告
python3 analyze_atomic_logs2.py --format text

# 仅生成 Word 报告
python3 analyze_atomic_logs2.py --format docx
```

### 4. 指定输出文件名

```bash
python3 analyze_atomic_logs2.py --output my_report
```

输出文件：
- `my_report.html`
- `my_report.xlsx`
- `my_report.txt`
- `my_report.docx`

### 5. 完整示例

```bash
python3 analyze_atomic_logs2.py \
    --log-dir /opt/bas/logs \
    --report-dir /opt/bas/reports \
    --format html \
    --output security_report_20260318
```

## 日志文件格式要求

脚本分析 `.log` 格式的日志文件，文件名格式：

```
{技术ID}_{时间戳}.log
```

示例：`T1059_20260318_143025.log`

## 报告内容

### 1. HTML 报告

包含以下内容：
- **执行摘要** - 测试概览和关键发现
- **统计图表** - 通过/失败/错误比例图
- **战术分布** - MITRE ATT&CK 战术覆盖情况
- **详细结果** - 每个测试的执行详情
- **风险分析** - 按风险等级分类的测试结果
- **错误分析** - 错误类型统计和详情

### 2. Excel 报告

包含多个工作表：
- **Summary** - 测试摘要统计
- **Details** - 详细测试结果
- **By Technique** - 按技术ID分组统计
- **By Tactic** - 按战术分组统计
- **Errors** - 错误详情
- **Execution Times** - 执行时间分析

### 3. 文本报告

纯文本格式的报告，适合命令行查看或存档。

### 4. Word 报告

专业格式的 Word 文档，适合正式报告提交。

## 支持的 MITRE ATT&CK 战术

| 战术 | 说明 |
|------|------|
| 初始访问 | T1078, T1189, T1190 等 |
| 执行 | T1059, T1064, T1204, T1203 等 |
| 持久化 | T1136, T1547, T1053, T1543 等 |
| 权限提升 | T1548, T1068, T1134, T1055 等 |
| 防御规避 | T1027, T1112, T1070, T1036 等 |
| 凭据访问 | T1003, T1005, T1056, T1212 等 |
| 发现 | T1083, T1018, T1518, T1057 等 |
| 横向移动 | T1021, T1534, T1570 等 |
| 数据收集 | T1041, T1005, T1560 等 |
| 数据外泄 | T1048, T1041, T1020 等 |
| 命令与控制 | T1071, T1095, T1132 等 |

## 风险等级定义

| 等级 | 技术示例 | 说明 |
|------|----------|------|
| Critical | T1003, T1055, T1059, T1548 | 严重风险，可能导致凭据泄露或系统完全被控制 |
| High | T1021, T1048, T1071, T1136, T1547, T1053 | 高风险，可能导致横向移动或持久化 |
| Medium | T1083, T1018, T1056, T1057, T1518, T1036, T1070 | 中等风险，可能导致信息泄露 |
| Low | T1005, T1041, T1020, T1132, T1560, T1534, T1570 | 低风险，影响相对较小 |

## 输出示例

```
开始分析测试日志...
分析完成，共处理 45 个测试结果

============================================================
报告生成完成!
- /opt/bas/reports/security_validation_report_20260318_143025.html
- /opt/bas/reports/security_validation_report_20260318_143025.xlsx
- /opt/bas/reports/security_validation_report_20260318_143025.txt
- /opt/bas/reports/security_validation_report_20260318_143025.docx

详细统计:
  总测试数: 45
  通过: 38 (84.4%)
  失败: 5
  错误: 2
  平均执行时间: 12.35秒
  测试技术: 25种
  严重风险失败: 0
  高风险失败: 1
============================================================
```

## 错误类型分类

脚本自动识别以下错误类型：

| 错误类型 | 匹配模式 |
|----------|----------|
| 权限不足 | permission denied, access denied, unauthorized |
| 命令未找到 | command not found, 不是内部或外部命令 |
| 网络错误 | connection refused, timeout, network unreachable |
| 资源不足 | no space, memory, out of memory |
| 依赖缺失 | module not found, import error, no module |
| 配置错误 | config, configuration, 设置错误 |
| 语法错误 | syntax, invalid syntax, 语法错误 |

## 工作流程

```
日志文件 (.log)
       ↓
  解析日志内容
       ↓
  提取关键信息
   - 技术ID
   - 时间戳
   - 执行状态
   - 命令列表
   - 错误信息
       ↓
  统计分析
   - 通过率
   - 战术分布
   - 风险等级
   - 错误分类
       ↓
  生成报告
   - HTML
   - Excel
   - Text
   - Word
```

## 配置修改

可在脚本中修改默认配置：

```python
# 修改默认目录
analyzer = AtomicLogAnalyzer(
    log_dir="/your/log/path",
    report_dir="/your/report/path"
)

# 添加自定义技术描述
self.technique_descriptions["TXXXX"] = "技术描述"

# 添加自定义风险等级
self.risk_levels["critical"].append("TXXXX")
```

## 与 run_all_atomics.sh 配合使用

### 典型工作流程

```bash
# 1. 执行原子测试
./run_all_atomics.sh -l techniques.txt -s

# 2. 分析测试日志
python3 analyze_atomic_logs2.py --format html

# 3. 查看报告
# HTML 报告可在浏览器中打开
firefox /opt/bas/reports/security_validation_report_*.html
```

### 自动化执行

```bash
#!/bin/bash
# 自动化测试和分析脚本

# 执行测试
/opt/bas/run_all_atomics.sh -l /opt/bas/configs/techniques.txt -s

# 等待测试完成
sleep 10

# 生成报告
python3 /opt/bas/analyze_atomic_logs2.py \
    --log-dir /opt/bas/logs \
    --report-dir /opt/bas/reports \
    --format html
```

## 常见问题

### Q: 未找到可分析的日志文件

**原因**: 日志目录中没有 `.log` 文件

**解决方法**:
1. 确认日志目录路径正确
2. 先运行 `run_all_atomics.sh` 生成日志
3. 检查日志文件权限

### Q: Word 报告生成失败

**原因**: 未安装 `python-docx` 库

**解决方法**:
```bash
pip install python-docx
```

### Q: 中文显示乱码

**解决方法**:
1. 确保系统安装了中文字体
2. 使用 UTF-8 编码打开文件

### Q: Excel 报告打开失败

**原因**: 缺少 `openpyxl` 库

**解决方法**:
```bash
pip install openpyxl
```

## 注意事项

1. **日志格式**: 确保日志文件名符合 `{技术ID}_{时间戳}.log` 格式
2. **编码问题**: 日志文件应使用 UTF-8 编码
3. **磁盘空间**: 确保 report 目录有足够的存储空间
4. **依赖完整性**: 安装所有必需依赖以确保全部功能可用

## 版本历史

- v2.0 - 支持 HTML/Excel/Text/Word 多格式报告
- v1.0 - 初始版本，基础日志分析功能