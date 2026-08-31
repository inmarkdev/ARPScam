"""
局域网主机扫描器
自动检测局域网内的所有活跃主机，并更新配置文件
"""

import os
import sys
import re
import time
import subprocess
import ipaddress
import psutil
import toml
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self, config_file="config.toml"):
        self.config_file = config_file
        self.interface = "WLAN"
        self.local_ip = None
        self.subnet = None
        self.gateway_ip = None
        self.hosts = []
        
    def get_network_info(self):
        """获取本机网络信息"""
        dic = psutil.net_if_addrs()
        for adapter in dic:
            if self.interface in adapter:
                for snic in dic[adapter]:
                    if snic.family.name == 'AF_INET':
                        self.local_ip = snic.address
                        # 计算子网
                        ip_parts = self.local_ip.split('.')
                        self.subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                        return True
        return False
    
    def get_gateway(self):
        """获取网关 IP（改进版）"""
        try:
            if sys.platform.lower().startswith('win'):
                # 先获取本机 IP 所在的网络适配器
                result = subprocess.run(
                    ['ipconfig', '/all'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.split('\n')
                
                # 查找本机 IP 所在的适配器区域
                current_adapter = None
                gateway = None
                adapter_name = self.interface  # 使用配置中的接口名
                
                for i, line in enumerate(lines):
                    # 检测适配器名称
                    if '适配器' in line or 'adapter' in line.lower():
                        # 如果之前找到了适配器并记录了网关，则退出
                        if current_adapter and gateway:
                            break
                        current_adapter = line.strip()
                        continue
                    
                    # 如果在正确的适配器范围内查找
                    if current_adapter and adapter_name in current_adapter:
                        # 查找 IPv4 地址确认这是活跃适配器
                        if 'IPv4 地址' in line or 'IP Address' in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match and ip_match.group(1) == self.local_ip:
                                # 找到了本机 IP，继续查找网关
                                continue
                        
                        # 查找默认网关
                        if '默认网关' in line or 'Default Gateway' in line:
                            gateway_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if gateway_match:
                                gateway = gateway_match.group(1)
                                # 排除不合适的网关（以 fe80 开头等）
                                if gateway and not gateway.startswith('fe80'):
                                    self.gateway_ip = gateway
                                    return gateway
            else:
                # Linux 下获取网关
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'],
                    capture_output=True,
                    text=True
                )
                if result.stdout:
                    parts = result.stdout.split()
                    if len(parts) > 2:
                        self.gateway_ip = parts[2]
                        return self.gateway_ip
        except Exception as e:
            print(f"⚠️ 获取网关失败: {e}")
        
        # 如果获取失败，使用子网 + .1 作为默认网关
        if self.subnet:
            default_gateway = f"{self.subnet}.1"
            print(f"ℹ️ 使用默认网关: {default_gateway}")
            self.gateway_ip = default_gateway
            return self.gateway_ip
        
        return None

    def ping_host(self, ip):
        """Ping 单个主机"""
        try:
            param = '-n' if sys.platform.lower().startswith('win') else '-c'
            timeout = '500' if sys.platform.lower().startswith('win') else '1'
            
            result = subprocess.run(
                ['ping', param, '1', '-w', timeout, ip],
                capture_output=True,
                text=True,
                timeout=3
            )
            return result.returncode == 0
        except:
            return False
    
    def get_mac_from_arp(self, ip):
        """从 ARP 缓存获取 MAC 地址"""
        try:
            # 先 ping 一下确保在 ARP 缓存中
            self.ping_host(ip)
            time.sleep(0.3)
            
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ip in line:
                    mac_match = re.search(
                        r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
                        line
                    )
                    if mac_match:
                        return mac_match.group(1).replace('-', ':').upper()
        except:
            pass
        return None
    
    def scan_host(self, ip):
        """扫描单个主机"""
        if self.ping_host(ip):
            mac = self.get_mac_from_arp(ip)
            return {
                'ip': ip,
                'mac': mac if mac else 'auto',
                'alive': True
            }
        return None
    
    def scan_network(self, show_progress=True):
        """扫描整个网络"""
        if not self.subnet:
            if not self.get_network_info():
                print("❌ 无法获取网络信息")
                return []
        
        print(f"📡 扫描子网: {self.subnet}.0/24")
        
        # 生成 IP 列表
        ips = [f"{self.subnet}.{i}" for i in range(1, 255)]
        
        # 排除本机 IP
        if self.local_ip in ips:
            ips.remove(self.local_ip)
        
        self.hosts = []
        found = 0
        
        print(f"🔍 正在扫描 {len(ips)} 个主机...")
        print("   (这可能需要 30-60 秒)")
        
        # 使用线程池加速扫描
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    self.hosts.append(result)
                    found += 1
                    if show_progress:
                        print(f"   ✅ 发现: {result['ip']} (MAC: {result['mac']})")
        
        # 按 IP 排序
        self.hosts.sort(key=lambda x: [int(i) for i in x['ip'].split('.')])
        
        print(f"\n📊 扫描完成，发现 {found} 个活跃主机")
        return self.hosts
    
    def load_config(self):
        """加载现有配置"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return toml.load(f)
        except:
            return None
    
    def save_config(self, config):
        """保存配置文件"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                toml.dump(config, f)
            return True
        except:
            return False
    
    def update_config(self, dry_run=False):
        """更新配置文件"""
        print("\n" + "=" * 60)
        print("🔄 更新配置文件")
        print("=" * 60)
        
        # 扫描网络
        self.scan_network()
        
        if not self.hosts:
            print("❌ 未发现任何活跃主机")
            return False
        
        # 获取网关
        self.get_gateway()
        
        # 加载现有配置
        config = self.load_config()
        if not config:
            # 创建新配置 - 包含完整的 settings
            config = {
                'gateway': {
                    'ip': self.gateway_ip if self.gateway_ip else '192.168.1.1',
                    'mac': 'auto'
                },
                'targets': [],
                'settings': {
                    'interface': 'WLAN',
                    'interval': 1,           # 攻击包发送间隔（秒）
                    'duration': 0,           # 攻击持续时间（0=无限）
                    'auto_recovery': True,   # 停止后自动恢复 ARP 表
                    'verbose': False,        # 详细输出
                    'auto_update': True,     # 启用自动配置更新
                    'update_interval': 300   # 配置检查间隔（秒），默认5分钟
                }
            }
        else:
            # 如果 settings 不存在，自动添加
            if 'settings' not in config:
                config['settings'] = {
                    'interface': 'WLAN',
                    'interval': 1,
                    'duration': 0,
                    'auto_recovery': True,
                    'verbose': False,
                    'auto_update': True,
                    'update_interval': 300
                }
        
        # 更新网关
        if self.gateway_ip:
            config['gateway']['ip'] = self.gateway_ip
        
        # 更新目标列表
        existing_targets = {t['ip']: t for t in config.get('targets', [])}
        new_targets = []
        
        print(f"\n📋 发现的主机:")
        for host in self.hosts:
            ip = host['ip']
            mac = host['mac']
            
            # 跳过网关
            if ip == self.gateway_ip:
                print(f"   🌐 {ip} (网关) - MAC: {mac}")
                continue
            
            # 检查是否已存在
            if ip in existing_targets:
                old = existing_targets[ip]
                # 更新 MAC（如果是 auto 或者 MAC 变了）
                if old.get('mac') == 'auto' or old.get('mac') != mac:
                    print(f"   🔄 {ip} - 更新 MAC: {old.get('mac')} -> {mac}")
                    old['mac'] = mac
                else:
                    print(f"   ✅ {ip} - 已存在 (MAC: {mac})")
                new_targets.append(old)
            else:
                # 新增主机
                print(f"   ➕ {ip} - 新增 (MAC: {mac})")
                new_targets.append({
                    'name': f"Device-{ip.replace('.', '-')}",
                    'ip': ip,
                    'mac': mac if mac else 'auto',
                    'enabled': True
                })
        
        # 保留被禁用的目标
        for ip, target in existing_targets.items():
            if target.get('enabled') == False:
                if ip not in [t['ip'] for t in new_targets]:
                    print(f"   ⏸️  {ip} - 保持禁用状态")
                    new_targets.append(target)
        
        # 更新配置
        config['targets'] = new_targets
        
        if dry_run:
            print("\n📝 预览配置更新 (不保存):")
            print(toml.dumps(config))
            return True
        
        # 保存配置
        if self.save_config(config):
            print(f"\n✅ 配置文件已更新: {self.config_file}")
            print(f"   - 网关: {config['gateway']['ip']}")
            print(f"   - 活跃目标: {len([t for t in config['targets'] if t.get('enabled', True)])} 个")
            return True
        else:
            print("❌ 保存配置文件失败")
            return False


def main():
    """主函数"""
    print("=" * 60)
    print("🔍 局域网主机扫描器 v1.0")
    print("=" * 60)
    
    # 创建扫描器
    scanner = NetworkScanner("config.toml")
    
    # 获取网络信息
    if not scanner.get_network_info():
        print("❌ 无法获取网络信息")
        return
    
    print(f"📡 本机 IP: {scanner.local_ip}")
    print(f"📡 子网: {scanner.subnet}.0/24")
    
    # 获取网关
    gateway = scanner.get_gateway()
    if gateway:
        print(f"🌐 网关: {gateway}")
    
    print("\n选项:")
    print("  1. 扫描并更新配置文件")
    print("  2. 仅扫描预览 (不保存)")
    print("  3. 退出")
    
    choice = input("\n请选择 (1-3): ").strip()
    
    if choice == '1':
        scanner.update_config(dry_run=False)
    elif choice == '2':
        scanner.update_config(dry_run=True)
    else:
        print("退出")


if __name__ == "__main__":
    main()
