#!/bin/bash
# MITRE ATT&CK批量测试脚本
# 文件名: run_all_atomics.sh
# 用法: ./run_all_atomics.sh [选项]

set -e  # 遇到错误退出

# 配置变量
BASE_DIR="/opt/bas"
GOART_PATH="${BASE_DIR}/goart-linux"
LOG_DIR="${BASE_DIR}/logs"
REPORT_DIR="${BASE_DIR}/reports"
CONFIG_DIR="${BASE_DIR}/configs"
ATOMICS_PATH="/opt/atomic-red-team"  # 假设原子红队项目已克隆到此目录

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 创建必要的目录
mkdir -p "${LOG_DIR}" "${REPORT_DIR}" "${CONFIG_DIR}"

# 帮助信息
show_help() {
    echo "MITRE ATT&CK 批量测试脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help           显示此帮助信息"
    echo "  -t TECHNIQUE_ID      运行特定技术ID的测试 (如: T1059 或 'T1021.004 - Remote Services: SSH')"
    echo "  -c CATEGORY          按类别运行测试 (如: execution, persistence, privilege-escalation)"
    echo "  -l LIST_FILE         从文件读取技术列表"
    echo "  -s, --skip-failed    跳过失败的测试继续运行"
    echo "  -d, --dry-run        只显示将要运行的测试，但不实际执行"
    echo "  -v, --verbose        显示详细信息"
    echo "  --max-parallel N     最大并行进程数 (默认: 1)"
    echo "  --timeout SEC        单个测试超时时间 (默认: 300秒)"
    echo ""
    echo "配置文件格式支持:"
    echo "  每行一个技术，支持多种格式:"
    echo "    T1021.004"
    echo "    T1021.004 - Remote Services: SSH"
    echo "    T1021.004 Remote Services: SSH"
    echo "    # 注释行会被跳过"
    echo ""
    echo "示例:"
    echo "  $0                           运行所有测试"
    echo "  $0 -t T1059                  运行特定技术测试"
    echo "  $0 -t 'T1021.004 - SSH'      运行特定技术测试（完整格式）"
    echo "  $0 -c execution              运行执行类别测试"
    echo "  $0 -l techniques.txt         从文件读取测试列表"
    echo "  $0 -l techniques.txt -v      从文件读取并显示详细信息"
}

# 日志函数
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] ${level}: ${message}"
}

log_info() {
    log "INFO" "$1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 检查依赖
check_dependencies() {
    if [ ! -f "${GOART_PATH}" ]; then
        log_error "goart-linux 未找到: ${GOART_PATH}"
        exit 1
    fi
    
    if [ ! -x "${GOART_PATH}" ]; then
        chmod +x "${GOART_PATH}"
    fi
    
    # 检查原子红队项目
    if [ ! -d "${ATOMICS_PATH}" ]; then
        log_warning "原子红队项目目录不存在: ${ATOMICS_PATH}"
        log_info "可以通过以下命令克隆: git clone https://github.com/redcanaryco/atomic-red-team.git ${ATOMICS_PATH}"
    fi
    
    # 检查必要的工具
    command -v jq >/dev/null 2>&1 || {
        log_warning "jq 未安装，某些功能可能受限"
        log_info "可以通过 'yum install jq' 或 'apt-get install jq' 安装"
    }
}

# 解析技术ID（支持多种格式）
# 支持格式：
#   T1021.004
#   T1021.004 - Remote Services: SSH
#   T1021.004 Remote Services: SSH
#   T1021.004,Remote Services: SSH
parse_technique_id() {
    local line="$1"
    local tech_id=""

    # 去除首尾空格
    line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # 跳过空行和注释行
    if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
        echo ""
        return
    fi

    # 提取技术ID（匹配 T开头+数字+可选.数字 的模式）
    # 支持格式: T1021.004, T1021, T1021.004 - xxx, T1021.004 xxx
    tech_id=$(echo "$line" | grep -oE '\bT[0-9]{4}(\.[0-9]{3})?\b' | head -1)

    echo "$tech_id"
}

# 从配置文件读取技术列表（支持完整格式）
read_techniques_from_file() {
    local file="$1"
    local techniques=""

    if [ ! -f "$file" ]; then
        log_error "配置文件不存在: ${file}"
        return 1
    fi

    log_info "读取配置文件: ${file}"

    while IFS= read -r line || [ -n "$line" ]; do
        local tech_id=$(parse_technique_id "$line")

        if [ -n "$tech_id" ]; then
            # 检查是否已存在，避免重复
            if [[ ! " $techniques " =~ " $tech_id " ]]; then
                techniques="${techniques} ${tech_id}"
                if [ "$VERBOSE" = "true" ]; then
                    log_info "解析到技术ID: ${tech_id} (原始行: ${line})"
                fi
            fi
        fi
    done < "$file"

    # 去除首尾空格
    techniques=$(echo "$techniques" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    echo "$techniques"
}

# 获取所有技术列表
get_all_techniques() {
    # 如果使用本地原子红队项目
    if [ -d "${ATOMICS_PATH}/atomics" ]; then
        find "${ATOMICS_PATH}/atomics" -type d -name "T*" | \
            sed 's|.*/||' | sort
    else
        # 从MITRE ATT&CK获取技术列表（示例）
        # 这里可以替换为实际获取技术列表的方法
        echo "T1003 T1005 T1012 T1016 T1018 T1021 T1027 T1036 T1046 T1047 T1049 T1053 T1055 T1059 T1068 T1070 T1071 T1072 T1078 T1082 T1083 T1090 T1095 T1098 T1102 T1105 T1106 T1110 T1112 T1113 T1119 T1120 T1124 T1125 T1129 T1132 T1133 T1134 T1135 T1136 T1137 T1140 T1176 T1187 T1189 T1190 T1195 T1197 T1199 T1200 T1201 T1202 T1203 T1204 T1205 T1210 T1211 T1212 T1213 T1216 T1217 T1218 T1219 T1220 T1221 T1222"
    fi
}

# 按类别获取技术列表
get_techniques_by_category() {
    local category="$1"
    # 这里可以根据类别过滤技术
    # 由于原子红队项目结构，可以使用metadata.json中的信息
    # 这是一个简化的示例
    case "$category" in
        "execution")
            echo "T1059 T1064 T1204 T1569 T1203"
            ;;
        "persistence")
            echo "T1136 T1547 T1053 T1505 T1137"
            ;;
        "privilege-escalation")
            echo "T1548 T1068 T1134 T1547 T1574"
            ;;
        "defense-evasion")
            echo "T1027 T1112 T1070 T1140 T1548"
            ;;
        "discovery")
            echo "T1016 T1018 T1033 T1046 T1082"
            ;;
        "lateral-movement")
            echo "T1021 T1077 T1091 T1210 T1550"
            ;;
        "collection")
            echo "T1005 T1113 T1114 T1115 T1119"
            ;;
        "exfiltration")
            echo "T1020 T1030 T1041 T1048 T1052"
            ;;
        "command-and-control")
            echo "T1071 T1095 T1132 T1571 T1572"
            ;;
        *)
            log_error "未知类别: ${category}"
            exit 1
            ;;
    esac
}

# 运行单个测试
run_technique_test() {
    local technique="$1"
    local test_index="$2"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local log_file="${LOG_DIR}/${technique}_${timestamp}.log"
    local report_file="${REPORT_DIR}/${technique}_${timestamp}.yaml"
    
    log_info "开始测试: ${technique} (索引: ${test_index})"
    
    # 构造goart命令
    local cmd="${GOART_PATH} --technique ${technique}"
    
    if [ -n "${test_index}" ] && [ "${test_index}" != "-1" ]; then
        cmd="${cmd} --index ${test_index}"
    fi
    
    if [ -d "${ATOMICS_PATH}" ]; then
        cmd="${cmd} --local-atomics-path ${ATOMICS_PATH}"
    fi
    
    # 执行测试
    if [ "$DRY_RUN" = "true" ]; then
        log_info "将执行命令: ${cmd}"
        return 0
    fi
    
    # 设置超时
    if [ -n "$TIMEOUT" ]; then
        timeout_cmd="timeout ${TIMEOUT}"
    else
        timeout_cmd=""
    fi
    
    # 执行并记录输出
    if $timeout_cmd bash -c "${cmd}" 2>&1 | tee "${log_file}"; then
        # 复制生成的YAML文件到报告目录
        if [ -f "atomic-test-executor-execution-${technique}-*.yaml" ]; then
            cp atomic-test-executor-execution-${technique}-*.yaml "${report_file}" 2>/dev/null || true
        fi
        
        # 检查测试结果
        if grep -q "Test completed successfully" "${log_file}"; then
            log_success "测试 ${technique} 成功完成"
            return 0
        elif grep -q "Test failed" "${log_file}"; then
            log_warning "测试 ${technique} 失败"
            return 1
        else
            log_info "测试 ${technique} 完成 (状态未知)"
            return 0
        fi
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "测试 ${technique} 超时"
        else
            log_error "测试 ${technique} 执行错误 (退出码: $exit_code)"
        fi
        return 1
    fi
}

# 批量运行测试
run_batch_tests() {
    local techniques="$1"
    local total=$(echo "$techniques" | wc -w)
    local current=0
    local successes=0
    local failures=0
    local skipped=0
    
    log_info "开始批量测试，共 ${total} 个技术"
    
    # 创建结果汇总文件
    local summary_file="${REPORT_DIR}/test_summary_$(date '+%Y%m%d_%H%M%S').txt"
    echo "MITRE ATT&CK 测试结果汇总" > "${summary_file}"
    echo "测试时间: $(date '+%Y-%m-%d %H:%M:%S')" >> "${summary_file}"
    echo "========================================" >> "${summary_file}"
    
    # 如果设置了并行执行
    if [ "$MAX_PARALLEL" -gt 1 ]; then
        log_info "启用并行执行，最大 ${MAX_PARALLEL} 个进程"
    fi
    
    for technique in $techniques; do
        current=$((current + 1))
        log_info "[${current}/${total}] 处理技术: ${technique}"
        
        # 运行测试
        if run_technique_test "$technique" "$TEST_INDEX"; then
            successes=$((successes + 1))
            echo "${technique}: SUCCESS" >> "${summary_file}"
        else
            failures=$((failures + 1))
            echo "${technique}: FAILED" >> "${summary_file}"
            
            if [ "$SKIP_FAILED" != "true" ]; then
                log_error "测试失败，停止执行 (使用 -s 选项跳过失败)"
                break
            fi
        fi
        
        # 添加间隔，避免系统负载过高
        sleep 1
    done
    
    # 输出总结
    echo ""
    echo "========================================"
    echo "测试完成总结:"
    echo "总测试数: ${total}"
    echo "成功: ${successes}"
    echo "失败: ${failures}"
    echo "跳过: ${skipped}"
    echo "========================================"
    
    # 更新总结文件
    echo "" >> "${summary_file}"
    echo "总结:" >> "${summary_file}"
    echo "总测试数: ${total}" >> "${summary_file}"
    echo "成功: ${successes}" >> "${summary_file}"
    echo "失败: ${failures}" >> "${summary_file}"
    echo "跳过: ${skipped}" >> "${summary_file}"
    echo "详细日志请查看: ${LOG_DIR}/" >> "${summary_file}"
    
    log_info "详细结果已保存到: ${summary_file}"
    
    if [ $failures -eq 0 ]; then
        log_success "所有测试成功完成!"
    else
        log_warning "有 ${failures} 个测试失败"
    fi
}

# 主函数
main() {
    # 解析参数
    TECHNIQUE_ID=""
    CATEGORY=""
    LIST_FILE=""
    SKIP_FAILED="false"
    DRY_RUN="false"
    VERBOSE="false"
    MAX_PARALLEL=1
    TIMEOUT=300
    TEST_INDEX=""  # 默认运行所有测试
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t)
                TECHNIQUE_ID="$2"
                shift 2
                ;;
            -c)
                CATEGORY="$2"
                shift 2
                ;;
            -l)
                LIST_FILE="$2"
                shift 2
                ;;
            -s|--skip-failed)
                SKIP_FAILED="true"
                shift
                ;;
            -d|--dry-run)
                DRY_RUN="true"
                shift
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            --max-parallel)
                MAX_PARALLEL="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --index)
                TEST_INDEX="$2"
                shift 2
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 检查依赖
    check_dependencies
    
    # 获取要测试的技术列表
    local techniques=""
    
    if [ -n "$TECHNIQUE_ID" ]; then
        # 运行单个技术（也支持完整格式）
        TECHNIQUE_ID=$(parse_technique_id "$TECHNIQUE_ID")
        if [ -z "$TECHNIQUE_ID" ]; then
            log_error "无法解析技术ID: $TECHNIQUE_ID"
            exit 1
        fi
        techniques="$TECHNIQUE_ID"
    elif [ -n "$CATEGORY" ]; then
        # 运行指定类别
        techniques=$(get_techniques_by_category "$CATEGORY")
    elif [ -n "$LIST_FILE" ] && [ -f "$LIST_FILE" ]; then
        # 从文件读取（支持完整格式）
        techniques=$(read_techniques_from_file "$LIST_FILE")
        if [ -z "$techniques" ]; then
            log_error "配置文件中未找到有效的技术ID: ${LIST_FILE}"
            exit 1
        fi
    else
        # 运行所有技术
        techniques=$(get_all_techniques)
    fi
    
    if [ -z "$techniques" ]; then
        log_error "未找到要测试的技术"
        exit 1
    fi
    
    # 显示将要运行的测试
    log_info "将要测试以下技术:"
    echo "$techniques" | tr ' ' '\n' | nl
    echo ""
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "干运行模式，不实际执行测试"
        exit 0
    fi
    
    # 确认
    read -p "是否继续执行测试? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "测试已取消"
        exit 0
    fi
    
    # 运行批量测试
    run_batch_tests "$techniques"
}

# 运行主函数
main "$@"
