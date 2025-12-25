import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


class DeviceScanner(object):
    """Android设备网络扫描器，负责本地网络检测和ADB设备发现。"""
    
    @staticmethod
    def get_local_network_prefixes():
        """获取本机所有网络接口的IP段。"""
        network_prefixes = []
        try:
            # 获取所有网络接口信息
            import socket
            hostname = socket.gethostname()
            
            # 方法1: 通过hostname获取IP
            try:
                local_ip = socket.gethostbyname(hostname)
                prefix = ".".join(local_ip.split(".")[:-1])
                network_prefixes.append((prefix, local_ip))
                print(f"Local IP: {local_ip}, Network: {prefix}.x")
            except:
                pass
            
            # 方法2: 通过socket连接外部地址来获取本机IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                prefix = ".".join(local_ip.split(".")[:-1])
                if not any(p[0] == prefix for p in network_prefixes):
                    network_prefixes.append((prefix, local_ip))
                    print(f"Local IP (via socket): {local_ip}, Network: {prefix}.x")
            except:
                pass
            
            # 如果还是没有找到，使用默认值
            if not network_prefixes:
                print("Could not determine local network, using 192.168.1.x")
                network_prefixes.append(("192.168.1", "192.168.1.0"))
                
        except Exception as e:
            print(f"Error detecting network: {e}, using 192.168.1.x")
            network_prefixes.append(("192.168.1", "192.168.1.0"))
        
        return network_prefixes

    @staticmethod
    def check_adb_device(ip, timeout=2):
        """检查单个IP是否有ADB设备，返回IP或None。"""
        ip_with_port = f"{ip}:5555"
        try:
            result = subprocess.run(
                ["adb", "connect", ip_with_port],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if "connected" in result.stdout.lower() or "already connected" in result.stdout.lower():
                return ip_with_port
        except Exception as e:
            pass
        return None

    @staticmethod
    def parse_network_prefix(network_input):
        """解析和规范化网段输入，支持CIDR表示法。
        
        支持多种格式：
        - 192.168.100 (C类网段)
        - 192.168.100.0 (网段地址)
        - 192.168.100.0/24 (CIDR格式 - 单个C类网段)
        - 192.168.100.0/23 (CIDR格式 - 两个C类网段)
        - 192.168.100.0/25 (CIDR格式 - C类网段的一半)
        - 192.168.100.* (通配符格式)
        
        Returns:
            list: 包含一个或多个网段前缀的列表，如['192.168.100', '192.168.101']
        """
        if not network_input:
            return None
        
        network_input = network_input.strip()
        
        # 移除末尾的点号
        if network_input.endswith('.'):
            network_input = network_input[:-1]
        
        # 处理通配符格式 (192.168.100.*)
        if network_input.endswith('.*'):
            network_input = network_input[:-2]
        
        # 处理CIDR格式 (192.168.100.0/24)
        if '/' in network_input:
            try:
                ip_part, mask = network_input.split('/')
                mask = int(mask)
                
                # 将IP转换为32位整数
                parts = ip_part.split('.')
                if len(parts) != 4:
                    print(f"Invalid IP format: {ip_part}")
                    return None
                
                ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
                
                # 创建掩码
                mask_int = (0xffffffff << (32 - mask)) & 0xffffffff
                
                # 获取网段的起始IP
                network_int = ip_int & mask_int
                
                # 获取网段的广播IP
                broadcast_int = network_int | (~mask_int & 0xffffffff)
                
                # 生成网段前缀列表
                prefixes = set()
                current_ip = network_int
                
                # 收集所有覆盖的C类网段前缀
                while current_ip <= broadcast_int:
                    # 提取前三个八位数（C类网段的前缀）
                    third_octet = (current_ip >> 8) & 0xff
                    first_octet = (current_ip >> 24) & 0xff
                    second_octet = (current_ip >> 16) & 0xff
                    
                    prefix = f"{first_octet}.{second_octet}.{third_octet}"
                    prefixes.add(prefix)
                    
                    # 移到下一个IP
                    current_ip += 1
                
                prefixes = sorted(list(prefixes))
                
                if prefixes:
                    print(f"Parsed CIDR {ip_part}/{mask} to {len(prefixes)} network prefix(es): {', '.join(prefixes)}")
                    return prefixes
                else:
                    return None
                    
            except ValueError as e:
                print(f"Invalid CIDR format: {network_input}, error: {e}")
                return None
        
        # 处理标准格式 (192.168.100.0 或 192.168.100)
        parts = network_input.split('.')
        if len(parts) == 4:
            # 移除第四个八位数
            network_input = '.'.join(parts[:3])
        elif len(parts) == 3:
            # 已经是标准格式
            pass
        else:
            print(f"Invalid network format: {network_input}")
            return None
        
        return [network_input]

    @staticmethod
    def scan_network_for_devices(network_prefix=None, timeout=2, max_workers=50):
        """使用多线程扫描本地网络中的Android设备。
        
        Args:
            network_prefix: 指定网段前缀，支持多种格式：
                           - 192.168.100 (C类网段)
                           - 192.168.100.0 (网段地址)
                           - 192.168.100.0/24 (CIDR格式 - 单个C类网段)
                           - 192.168.100.0/23 (CIDR格式 - 两个C类网段)
                           - 192.168.100.* (通配符格式)
                           如果为None则自动检测本机网段
            timeout: 单个IP的超时时间（秒）
            max_workers: 线程数
        """
        print("Scanning local network for Android devices (using multi-threading)...")
        found_devices = []
        
        # 确定要扫描的网段
        if network_prefix is None:
            # 自动检测本机网段
            network_prefixes = DeviceScanner.get_local_network_prefixes()
            prefixes_to_scan = [prefix for prefix, _ in network_prefixes]
        else:
            # 使用指定的网段，进行规范化
            parsed_prefixes = DeviceScanner.parse_network_prefix(network_prefix)
            if parsed_prefixes is None:
                print("Failed to parse network prefix, using auto-detection instead")
                network_prefixes = DeviceScanner.get_local_network_prefixes()
                prefixes_to_scan = [prefix for prefix, _ in network_prefixes]
            else:
                prefixes_to_scan = parsed_prefixes
        
        # 构建所有需要检查的IP地址
        ips_to_check = []
        for prefix in prefixes_to_scan:
            for i in range(1, 255):
                ips_to_check.append(f"{prefix}.{i}")
        
        print(f"Checking {len(ips_to_check)} IP addresses with {max_workers} threads...")
        
        # 使用ThreadPoolExecutor进行多线程扫描
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(DeviceScanner.check_adb_device, ip, timeout): ip for ip in ips_to_check}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_devices.append(result)
                    print(f"Found device: {result}")
        return found_devices
