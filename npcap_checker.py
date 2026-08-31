"""
Npcap 检测模块

用于检测 Windows 系统上的 Npcap 安装状态和功能。

核心判断：
1. npcap.sys 驱动是否存在
2. Npcap 服务是否存在并运行
3. Scapy 是否能够正常枚举网络接口

注册表、DLL、安装目录仅作为辅助信息。
"""

import os
import subprocess
import sys
import time
import winreg


# ============================================================
# 路径
# ============================================================

NPCAP_DRIVER_PATH = r"C:\Windows\System32\drivers\npcap.sys"

NPCAP_DIR = r"C:\Program Files\Npcap"

NPCAP_SYSTEM32_DIR = r"C:\Windows\System32\Npcap"

NPCAP_DLL_PATHS = [
    os.path.join(NPCAP_SYSTEM32_DIR, "wpcap.dll"),
    os.path.join(NPCAP_SYSTEM32_DIR, "packet.dll"),
]


# ============================================================
# 注册表检测
# ============================================================

def check_npcap_installed():
    """
    尝试从注册表获取 Npcap 安装信息。

    注意：
    注册表检测仅作为辅助信息，不能作为判断 Npcap
    是否可用的唯一依据。

    返回:
        (installed, version, install_path)
    """

    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Npcap",
    ]

    for reg_path in reg_paths:

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                reg_path
            )

            try:
                display_name = winreg.QueryValueEx(
                    key,
                    "DisplayName"
                )[0]
            except Exception:
                display_name = "Npcap"

            try:
                version = winreg.QueryValueEx(
                    key,
                    "DisplayVersion"
                )[0]
            except Exception:
                version = None

            try:
                install_path = winreg.QueryValueEx(
                    key,
                    "InstallLocation"
                )[0]
            except Exception:
                install_path = None

            winreg.CloseKey(key)

            if "Npcap" in str(display_name):
                return True, version, install_path

        except FileNotFoundError:
            continue

        except Exception:
            continue

    return False, None, None


# ============================================================
# 文件检测
# ============================================================

def check_npcap_files():
    """
    检查 Npcap 相关文件。
    """

    found_items = []

    # Npcap 安装目录
    if os.path.isdir(NPCAP_DIR):
        found_items.append(
            f"✓ Npcap目录: {NPCAP_DIR}"
        )

    # System32 Npcap 目录
    if os.path.isdir(NPCAP_SYSTEM32_DIR):
        found_items.append(
            f"✓ System32 Npcap目录: {NPCAP_SYSTEM32_DIR}"
        )

    # DLL
    for dll_path in NPCAP_DLL_PATHS:

        if os.path.isfile(dll_path):

            dll_name = os.path.basename(dll_path)

            found_items.append(
                f"✓ {dll_name}: {dll_path}"
            )

    # 驱动
    if os.path.isfile(NPCAP_DRIVER_PATH):

        found_items.append(
            f"✓ 驱动: {NPCAP_DRIVER_PATH}"
        )

    return found_items


# ============================================================
# 服务检测
# ============================================================

def check_npcap_service():
    """
    检查 Npcap 服务。

    返回:
        (是否运行, 状态描述)
    """

    try:

        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=5
        )

        stdout = result.stdout
        stderr = result.stderr

        if "RUNNING" in stdout:
            return True, "运行中"

        if "STOPPED" in stdout:
            return False, "已停止"

        if (
            "does not exist" in stdout.lower()
            or "1060" in stdout
            or "不存在" in stdout
        ):
            return False, "服务不存在"

        if stderr:
            return False, stderr.strip()

        return False, "未知状态"

    except subprocess.TimeoutExpired:
        return False, "查询超时"

    except Exception as e:
        return False, f"查询失败: {e}"


# ============================================================
# 驱动检测
# ============================================================

def check_npcap_driver():
    """
    检查 Npcap 核心驱动。

    Npcap:
        npcap.sys

    注意：
        WinPcap 使用的是 npf.sys，
        不能使用 npf.sys 判断 Npcap。
    """

    try:

        if not os.path.isfile(NPCAP_DRIVER_PATH):
            return False, "npcap.sys 驱动文件不存在"

        file_stat = os.stat(NPCAP_DRIVER_PATH)

        file_size = file_stat.st_size

        file_time = time.ctime(
            file_stat.st_mtime
        )

        return True, (
            f"存在 | "
            f"大小: {file_size:,} 字节 | "
            f"修改时间: {file_time}"
        )

    except Exception as e:

        return False, str(e)


# ============================================================
# Scapy 功能检测
# ============================================================

def test_npcap_functionality():
    """
    使用 Scapy 测试 Npcap 是否能够正常访问网络接口。
    """

    try:

        from scapy.all import get_if_list

    except ImportError:

        return (
            False,
            "Scapy 未安装，请运行: pip install scapy"
        )

    except Exception as e:

        return (
            False,
            f"Scapy 导入失败: {e}"
        )

    try:

        interfaces = get_if_list()

        if not interfaces:

            return (
                False,
                "Scapy 未检测到网络接口"
            )

        return (
            True,
            f"检测到 {len(interfaces)} 个网络接口"
        )

    except Exception as e:

        return (
            False,
            f"功能测试失败: {e}"
        )


# ============================================================
# 快速检测
# ============================================================

def quick_npcap_check():
    """
    快速检测 Npcap。

    核心判断：
        npcap.sys 是否存在。

    返回:
        (是否存在, 描述)
    """

    try:

        if os.path.isfile(NPCAP_DRIVER_PATH):

            return (
                True,
                f"找到 Npcap 驱动: {NPCAP_DRIVER_PATH}"
            )

        # 兼容检查 Npcap 目录
        if os.path.isdir(NPCAP_DIR):

            return (
                True,
                f"找到 Npcap 安装目录: {NPCAP_DIR}"
            )

        # 注册表作为最后的辅助判断
        installed, version, install_path = (
            check_npcap_installed()
        )

        if installed:

            if version:
                return (
                    True,
                    f"注册表检测到 Npcap {version}"
                )

            return (
                True,
                "注册表检测到 Npcap"
            )

        return False, "未找到 Npcap"

    except Exception as e:

        return False, f"检测失败: {e}"


# ============================================================
# 获取版本
# ============================================================

def get_npcap_version():
    """
    获取 Npcap 版本。

    优先从注册表读取。
    """

    installed, version, _ = (
        check_npcap_installed()
    )

    if installed and version:
        return version

    return None


# ============================================================
# 全面检测
# ============================================================

def comprehensive_npcap_check():
    """
    全面的 Npcap 检测。

    返回:
        dict
    """

    results = {

        "installed": False,

        "version": None,

        "install_path": None,

        "files": [],

        "service": False,

        "service_status": "未知",

        "driver": False,

        "driver_info": "未知",

        "functional": False,

        "function_info": "未测试",

        "available": False,
    }

    # --------------------------------------------------------
    # 1. 注册表
    # --------------------------------------------------------

    (
        registry_installed,
        version,
        install_path
    ) = check_npcap_installed()

    results["version"] = version
    results["install_path"] = install_path

    # --------------------------------------------------------
    # 2. 文件
    # --------------------------------------------------------

    results["files"] = check_npcap_files()

    # --------------------------------------------------------
    # 3. 服务
    # --------------------------------------------------------

    (
        service_running,
        service_status
    ) = check_npcap_service()

    results["service"] = service_running
    results["service_status"] = service_status

    # --------------------------------------------------------
    # 4. 驱动
    # --------------------------------------------------------

    (
        driver_exists,
        driver_info
    ) = check_npcap_driver()

    results["driver"] = driver_exists
    results["driver_info"] = driver_info

    # --------------------------------------------------------
    # 5. Scapy 功能
    # --------------------------------------------------------

    (
        functional,
        function_info
    ) = test_npcap_functionality()

    results["functional"] = functional
    results["function_info"] = function_info

    # --------------------------------------------------------
    # 6. 判断安装状态
    # --------------------------------------------------------

    # 不再要求注册表必须存在。
    #
    # npcap.sys 存在即可认为 Npcap 核心组件存在。
    #
    results["installed"] = driver_exists

    # --------------------------------------------------------
    # 7. 判断是否可用
    # --------------------------------------------------------

    results["available"] = (
        driver_exists
        and service_running
        and functional
    )

    return results


# ============================================================
# 打印检测结果
# ============================================================

def print_detection_results(results):
    """
    打印检测结果。
    """

    print("=" * 60)

    print("🔍 Npcap 检测结果")

    print("=" * 60)

    # --------------------------------------------------------
    # 注册表
    # --------------------------------------------------------

    print("\n📋 注册表检测:")

    if results["version"]:

        print("  ✅ 检测到 Npcap")

        print(
            f"  版本: {results['version']}"
        )

        if results["install_path"]:

            print(
                f"  路径: {results['install_path']}"
            )

    else:

        print(
            "  ⚠️ 未检测到注册表安装信息"
        )

        print(
            "  ℹ️ 这不影响 Npcap 核心功能判断"
        )

    # --------------------------------------------------------
    # 文件
    # --------------------------------------------------------

    print("\n📁 文件检测:")

    if results["files"]:

        print(
            f"  找到 {len(results['files'])} 个相关项目:"
        )

        for item in results["files"]:

            print(f"    {item}")

    else:

        print(
            "  ❌ 未找到 Npcap 文件"
        )

    # --------------------------------------------------------
    # 服务
    # --------------------------------------------------------

    print("\n🔄 服务检测:")

    if results["service"]:

        print(
            "  ✅ Npcap 服务运行中"
        )

    else:

        print(
            f"  ❌ 服务异常: "
            f"{results['service_status']}"
        )

    # --------------------------------------------------------
    # 驱动
    # --------------------------------------------------------

    print("\n🔌 驱动检测:")

    if results["driver"]:

        print("  ✅ 驱动存在")

        print(
            f"  {results['driver_info']}"
        )

    else:

        print("  ❌ 驱动不存在")

        print(
            f"  {results['driver_info']}"
        )

    # --------------------------------------------------------
    # 功能
    # --------------------------------------------------------

    print("\n🧪 功能测试:")

    if results["functional"]:

        print("  ✅ 功能正常")

    else:

        print("  ❌ 功能异常")

    print(
        f"  {results['function_info']}"
    )

    # --------------------------------------------------------
    # 总结
    # --------------------------------------------------------

    print("\n" + "=" * 60)

    print("📊 总结:")

    if results["available"]:

        print(
            "  ✅ Npcap 已正确安装并可正常使用"
        )

    elif results["installed"]:

        print(
            "  ⚠️ Npcap 已安装，但功能异常"
        )

        print(
            "  💡 请检查 Npcap 服务和 Scapy"
        )

    else:

        print(
            "  ❌ Npcap 核心组件不存在"
        )

        print(
            "  💡 请安装 Npcap"
        )

    print("=" * 60)

    return results["available"]


# ============================================================
# 安装指南
# ============================================================

def install_npcap_guide():
    """
    显示 Npcap 安装指南。
    """

    print("\n📖 Npcap 安装指南:")

    print("=" * 60)

    print("1. 下载 Npcap:")

    print(
        "   https://npcap.com/#download"
    )

    print()

    print("2. 安装注意事项:")

    print(
        "   - 以管理员权限运行安装程序"
    )

    print(
        "   - 如果程序需要 WinPcap API 兼容性，"
        "勾选 WinPcap-compatible Mode"
    )

    print(
        "   - 安装完成后建议重启电脑"
    )

    print()

    print("3. 验证安装:")

    print(
        "   - 重新运行本检测模块"
    )

    print(
        "   - 确认 npcap.sys 存在"
    )

    print(
        "   - 确认 Npcap 服务运行"
    )

    print(
        "   - 确认 Scapy 能够检测网络接口"
    )

    print("=" * 60)


# ============================================================
# 主程序使用的检测入口
# ============================================================

def check_npcap_before_attack(ask_user=True):
    """
    主程序启动前检测 Npcap。

    保留原来的函数名，避免修改主程序。

    返回:
        True  = Npcap 可用
        False = Npcap 不可用
    """

    print("\n" + "=" * 60)

    print("🔍 检测 Npcap...")

    print("=" * 60)

    # --------------------------------------------------------
    # 综合检测
    # --------------------------------------------------------

    results = comprehensive_npcap_check()

    # --------------------------------------------------------
    # 显示核心结果
    # --------------------------------------------------------

    if results["driver"]:

        print(
            "✅ Npcap 驱动正常"
        )

    else:

        print(
            "❌ Npcap 驱动不存在"
        )

    if results["service"]:

        print(
            "✅ Npcap 服务运行中"
        )

    else:

        print(
            f"❌ Npcap 服务异常: "
            f"{results['service_status']}"
        )

    if results["functional"]:

        print(
            f"✅ Scapy 功能正常: "
            f"{results['function_info']}"
        )

    else:

        print(
            f"❌ Scapy 功能异常: "
            f"{results['function_info']}"
        )

    # --------------------------------------------------------
    # 最终判断
    # --------------------------------------------------------

    if results["available"]:

        print(
            "\n✅ Npcap 已正确安装并可正常使用"
        )

        return True

    # --------------------------------------------------------
    # 不可用
    # --------------------------------------------------------

    print(
        "\n❌ Npcap 当前不可用"
    )

    # --------------------------------------------------------
    # 是否允许用户继续
    # --------------------------------------------------------

    if not ask_user:

        return False

    print()

    print(
        "是否仍然继续程序？(y/n): ",
        end=""
    )

    try:

        choice = input().strip().lower()

    except (EOFError, KeyboardInterrupt):

        print()

        return False

    if choice == "y":

        print(
            "\n⚠️ 用户选择继续运行"
        )

        return True

    print(
        "\n请检查 Npcap 后重试"
    )

    return False


# ============================================================
# 直接运行
# ============================================================

if __name__ == "__main__":
    print("Npcap 检测工具")
    print("=" * 60)
    results = comprehensive_npcap_check()
    print_detection_results(results)
    if not results["available"]:
        print()
        install_npcap_guide()
