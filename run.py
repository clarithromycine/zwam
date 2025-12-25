import os,sys,time


from zwam.wam import Wam
sys.path.append(".")
import frida
import threading
from common.utils import Utils
from lxml import etree
from common.device_scanner import DeviceScanner




class FridaRunner(object):
    """Frida脚本运行器，负责WhatsApp应用的Frida hook和数据收集。"""

    CLASS_MAP = {
        "WhatsApp Business":["com.whatsapp.w4b","com.whatsapp.w4b/com.whatsapp.Main"],
        "WhatsApp":["com.whatsapp","com.whatsapp/com.whatsapp.Main"]
    }
    
    def __init__(self, js_code, device_manager, device_id, process_name):
        self.js_code = js_code
        self.device_manager = device_manager
        self.device_id = device_id
        self.process_name = process_name
        self.class_name = FridaRunner.CLASS_MAP.get(process_name)[0]
        self.activity_name = FridaRunner.CLASS_MAP.get(process_name)[1]        

    def on_message(self, message, data):           
        if message['type'] == 'send':
            msg = message['payload']
            if msg.startswith("["):
                if msg.startswith("[XML send] <iq xmlns='w:stats'"):                
                    parser = etree.XMLParser(remove_blank_text=True) 
                    xml = etree.XML(msg.replace("[XML send] ",""),parser)    
                    add = xml.find("{w:stats}add")                
                    result = Wam.deserializer(add.text)                
                    print("=== Record Timestamp:{0} ===\n{1}\n".format(int(time.time()),str(result)))            
            else:
                print(msg)    

    def on_detached(self, reason):
        print('[{0}-{1}] Frida script detached from PID {2}...'.format(self.device_id, self.process_name, self.pid))   

    def run(self):                
        device = self.device_manager.get_device(self.device_id)
        os.system("adb -s {0} shell am force-stop {1}".format(self.device_id, self.class_name))
        os.system("adb -s {0} shell am start {1}".format(self.device_id, self.activity_name))
        
        # 等待应用启动，最多尝试5次（5秒）
        max_retries = 5
        retry_count = 0
        self.pid = None
        
        while retry_count < max_retries:
            try:
                self.pid = device.get_process(self.process_name).pid
                print(f"[{self.device_id}-{self.process_name}] App started with PID {self.pid}")
                break
            except Exception as e:
                retry_count += 1
                if retry_count < max_retries:
                    print(f"[{self.device_id}-{self.process_name}] Waiting for app to start... ({retry_count}/{max_retries})")
                    time.sleep(1)
                else:
                    print(f"[{self.device_id}-{self.process_name}] Failed to start app after {max_retries} seconds")
                    raise
        
        try:
            self.session = device.attach(self.pid)
            self.script = self.session.create_script(self.js_code)
            self.session.on("detached", self.on_detached)
            self.script.on('message', self.on_message)
            print('[{0}-{1}] Frida script attached to PID {2}...'.format(self.device_id, self.process_name, self.pid))
            self.script.load()
        except Exception as e:
            print(f"[{self.device_id}-{self.process_name}] Error attaching to process: {e}")
            raise

    def stop(self):
        os.system("adb -s {0} shell am force-stop {1}".format(self.device_id, self.class_name))
                
    def runAsThread(self):
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True         
        self.thread.start()


if __name__ == "__main__":

    params, options = Utils.cmdLineParser(sys.argv)

    with open('android/frida_output.js', 'r', encoding="utf-8") as f:
        js_code = f.read()

    if js_code is None or js_code == "":
        print("JS code is empty")
        exit(1)
        
    runnerList = []
    manager = frida.get_device_manager()

    env = options.get("env", "smb_android")

    if env == "android":
        appName = "WhatsApp"
    else:
        appName = "WhatsApp Business"

    
    device = options.get('device', None)

    if device is None:
        # 没指定device，默认使用第一个usb设备
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
            # 获取指定的网段或为None（自动检测）
            network_prefix = options.get('network', None)
            if network_prefix:
                print(f"User specified network: {network_prefix}")
            network_devices = DeviceScanner.scan_network_for_devices(network_prefix=network_prefix)
            if network_devices:
                device = network_devices[0]
                print(f"Using network device: {device}")
            else:
                print("No devices found on local network either.")

    if device is not None:        
        print("device: {0}".format(device))
        device_ids = device.split(",")
        
        for device_id in device_ids:
            runner = FridaRunner(js_code, manager, device_id, appName)
            runnerList.append(runner)
            runner.runAsThread()
    else:
        print("No device connected.")
        exit(1)

                            
    sys.stdin.read()
