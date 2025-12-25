import os,sys,time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from zwam.wam import Wam
sys.path.append(".")
import frida
import threading
from common.utils import Utils
from lxml import etree

class FridaRunner(object):

    CLASS_MAP = {
        "WhatsApp Business":["com.whatsapp.w4b","com.whatsapp.w4b/com.whatsapp.Main"],
        "WhatsApp":["com.whatsapp","com.whatsapp/com.whatsapp.Main"]
    }


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
    def scan_network_for_devices(timeout=2, max_workers=50):
        """使用多线程扫描本地网络中的Android设备。"""
        print("Scanning local network for Android devices (using multi-threading)...")
        found_devices = []
        network_prefixes = FridaRunner.get_local_network_prefixes()
        
        # 构建所有需要检查的IP地址
        ips_to_check = []
        for prefix, _ in network_prefixes:
            for i in range(1, 255):
                ips_to_check.append(f"{prefix}.{i}")
        
        print(f"Checking {len(ips_to_check)} IP addresses with {max_workers} threads...")
        
        # 使用ThreadPoolExecutor进行多线程扫描
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(FridaRunner.check_adb_device, ip, timeout): ip for ip in ips_to_check}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_devices.append(result)
                    print(f"Found device: {result}")
        return found_devices
    
    def __init__(self, js_code, device_manager,device_id, process_name):
        self.js_code = js_code
        self.device_manager = device_manager
        self.device_id = device_id
        self.process_name = process_name
        self.class_name = FridaRunner.CLASS_MAP.get(process_name)[0]
        self.activity_name = FridaRunner.CLASS_MAP.get(process_name)[1]        

    def on_message(self, message, data):           
        if message['type'] == 'send':
            msg = message['payload']
            if msg.startswith("[XML send] <iq xmlns='w:stats'"):                
                parser = etree.XMLParser(remove_blank_text=True) 
                xml = etree.XML(msg.replace("[XML send] ",""),parser)    
                add = xml.find("{w:stats}add")                
                result = Wam.deserializer(add.text)                
                print("=== Record Timestamp:{0} ===\n{1}\n".format(int(time.time()),str(result)))                

    def on_detached(self,reason):
        print('[{0}-{1}] Frida script detached from PID {2}...'.format(self.device_id,self.process_name,self.pid))   

    def run(self):                
        device = self.device_manager.get_device(self.device_id)
        os.system("adb -s {0} shell am force-stop {1}".format(self.device_id, self.class_name))
        os.system("adb -s {0} shell am start {1}".format(self.device_id, self.activity_name))
        #time.sleep(5)  # wait for the app to start
        self.pid = device.get_process(self.process_name).pid
        self.session = device.attach(self.pid)
        self.script = self.session.create_script(self.js_code)
        self.session.on("detached",self.on_detached)
        self.script.on('message', self.on_message)
        print('[{0}-{1}] Frida script attached to PID {2}...'.format(self.device_id,self.process_name,self.pid))
        self.script.load()

    def stop(self):
        os.system("adb -s {0} shell am force-stop {1}".format(self.device_id, self.class_name))        
                
    def runAsThread(self):
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True         
        self.thread.start()        


if __name__ == "__main__":

    params,options = Utils.cmdLineParser(sys.argv)

    with open('android/frida_output.js', 'r', encoding="utf-8") as f:
        js_code = f.read()

    if js_code is None or js_code == "":
        print("JS code is empty")
        exit(1)
        
    runnerList = []
    manager = frida.get_device_manager()

    env = options.get("env","smb_android")

    if env=="android":
        appName = "WhatsApp"
    else:
        appName = "WhatsApp Business"

    
    device = options.get('device',None)

    if device is None:
        #没指定device，默认使用第一个usb设备
        manager = frida.get_device_manager()
        devices = manager.enumerate_devices()                    
        for item in devices:
            if item.type == 'usb':
                print("Found device: {0} ({1})".format(item.name, item.id))        
                device = item.id
                break
        
        # If no USB device found, scan the local network
        if device is None:
            print("No USB device found. Scanning local network for Android devices...")
            network_devices = FridaRunner.scan_network_for_devices()
            if network_devices:
                device = network_devices[0]
                print(f"Using network device: {device}")
            else:
                print("No devices found on local network either.")

    if device  is not None:        
        print("device: {0}".format(device))
        device_ids = device.split(",")
        
        for device_id in device_ids:
            runner = FridaRunner(js_code, manager,device_id, appName)
            runnerList.append(runner) 
            runner.runAsThread() 
    else:
        print("No device connected.")
        exit(1)

                            
    sys.stdin.read()
