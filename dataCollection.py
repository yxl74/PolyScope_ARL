from ppadb.client import Client as AdbClient
import argparse
import sys, os, time
import xml.etree.ElementTree as ET


#Function to initialize directories for PolyScope
def init_directories():
	if not os.path.isdir("./attribute_file"):
		os.mkdir("./attribute_file")
	if not os.path.isdir("./subgroup"):
		os.mkdir("./subgroup")
	if not os.path.isdir("./dac_result"):
		os.mkdir("./dac_result")
	if not os.path.isdir("./mac_policy"):
		os.mkdir("./mac_policy")
	if not os.path.isdir("./ls_lRZ"):
		os.mkdir("./ls_lRZ")
	if not os.path.isdir("./ps-Z-list"):
		os.mkdir("./ps-Z-list")
	if not os.path.isdir("./apks"):
		os.mkdir("./apks")
	if not os.path.isdir("./db_file"):
		os.mkdir("./db_file")

#Function to pull package list from Android Phone
def pull_pkg_list(device):
	client = AdbClient(host="127.0.0.1", port=5037)
	devices = client.devices()
	adb_device = devices[0]

	adb_device.shell("su -c \" cp /data/system/packages.list /sdcard/" + device + "_pkglist \"")
	adb_device.pull("/sdcard/" + device + "_pkglist", "./db_file/" + device + "_pkglist")

#Function to pull apk list from Android Phone
def pull_apk_list(device):
	client = AdbClient(host="127.0.0.1", port=5037)
	devices = client.devices()
	adb_device = devices[0]


	adb_device.shell("pm list packages -f | tee /sdcard/" + device + "_apk_list")
	adb_device.pull("/sdcard/" + device + "_apk_list", "./apks/" + device + "_apk_list")

#Function to pull apk files from phone
def copy_apk_to_sdcard(device):
	client = AdbClient(host="127.0.0.1", port=5037)
	devices = client.devices()
	adb_device = devices[0]

	with open("./apks/" + device + "_apk_list") as f:
		for line in f:
			fp = line[line.find("package:")+8:line.find(".apk")+4]
			folder = ""
			pkg_name = line[line.find(".apk")+5:-1]
			#print("su -c \"cp " + fp + " /sdcard/" + pkg_name+".apk\"")
			adb_device.shell("su -c \"cp " + fp + "  /sdcard/" + pkg_name+".apk\"")


#get apk files from devices
def pull_apk_files(device):
	#Init directory
	client = AdbClient(host="127.0.0.1", port=5037)
	devices = client.devices()
	adb_device = devices[0]
	
	with open("./apks/" + device + "_apk_list") as f:
		for line in f:
			fp = line[line.find("package:")+8:line.find(".apk")+4]
			folder = ""
			pkg_name = line[line.find(".apk")+5:-1]
			folder = "_app"

			os.system("adb pull /sdcard/" + pkg_name + ".apk ./apks/" + device + folder + "/" + pkg_name+".apk")
			adb_device.shell("su -c \"rm /sdcard/" + pkg_name +".apk\"")


def get_manifest_file(device):
	with open("./apks/" + device + "_apk_list") as f:
		for line in f:
			fp = line[line.find("package:")+8:line.find(".apk")+4]
			pkg_name = line[line.find(".apk")+5:-1]
			folder = "_app"

			os.system("apkanalyzer manifest print ./apks/" + device + folder + "/" + pkg_name + ".apk | tee ./apks/" + device + folder + "/" + pkg_name + ".manifest")



#Class to collect data from ROOTED Android Phone
class Phone:
    def __init__(self, device_name):
        client = client = AdbClient(host="127.0.0.1", port=5037)
        devices = client.devices()
        self.device = devices[0]
        self.name = device_name
    
    def shell(self,command):
        self.device.shell(command)
    
    def handler(self, connection):
        while True:
            data = connection.read_all()
            if not data:
                break
            data = data.decode('utf-8')
            lst = data.split("\n")
            self.package_list = lst
        connection.close()

    #This function returns a line of process list
    def get_ps(self,pkg_name):
        client = client = AdbClient(host="127.0.0.1", port=5037)
        devices = client.devices()
        device = devices[0]
        gname = ""
    
        def handler1(connection):
            data = connection.read_all()
            data = data.decode('utf-8')
            nonlocal gname
            gname = data
            connection.close()

        device.shell("su -c \"ps -A -o label:40,UID:20,GID:20,PID,NAME:40 | grep " + pkg_name + "\"", handler = handler1)
        return gname 
 
 
           
	#get process subgroup info
    def get_subgroup(self):
        self.device.push("subgroup.sh", "/sdcard/Download/subgroup.sh")
        self.device.shell("su -c \"mv /sdcard/Download/subgroup.sh /data/adb \"")
        self.device.shell("su -c \"chmod 777 /data/adb/subgroup.sh \"")
        self.device.shell("su -c \"/data/adb/subgroup.sh\"")
        self.device.shell("su -c \"rm /data/adb/subgroup.sh\"")
        self.device.pull("/sdcard/subgroup", "./subgroup/"+self.name)
        self.device.shell("su -c \"rm /sdcard/subgroup\"")

    #Function to start all activity
    def start_package(self, pkg_name, manifest_path):
        android_ns = ""
        with open(manifest_path, 'r')  as f:
            for line in f:
                if "xmlns" in line:
                    tmp = line.split()[0]
                    name = tmp.split("=")[0].split(":")[1]
                    str = tmp.split("=")[1][1:-1]
                    if name == "android":
                        android_ns = str
                        break
        if not android_ns:
            return
        print(manifest_path)
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        app = root.findall("application")
        if not app:
            return None
        acts = app[0].findall("activity")
        for activity in acts:
            attrib_name = "{" + android_ns + "}name"
            attrib_exp = "{" + android_ns + "}exported"
            act_name = activity.attrib[attrib_name]
    
            for intent_filter in activity.findall("intent-filter"):
                for action in intent_filter.findall("action"):
                    action_type = action.attrib["{" + android_ns + "}name"]
                    self.device.shell("su -c \"am start -n "+ pkg_name + "/" + act_name + " -a " + action_type + "\"")
                    time.sleep(0.5)
                    tmp = self.get_ps(pkg_name)
                    if tmp:
                        return tmp
        return None


    def advance_get_ps(self):
        extra_ps = []
        pkg_missing = []
        with open("./apks/" + self.name + "_apk_list", 'r') as f:
            for line in f:
                pkg_name = line[line.find(".apk")+5:-1]
                if "com.nearme.play" in pkg_name:
                     continue
                folder = self.name + "_app"
                manifest_path = "./apks/" + folder + "/" + pkg_name + ".manifest"
                if not os.path.exists(manifest_path):
                    continue
                ps_line = self.start_package(pkg_name, manifest_path)
                if ps_line:
                    extra_ps.append(ps_line)
                else:
                    pkg_missing.append(pkg_name)
        for line in extra_ps:
            print(line)
        with open("./ps-Z-list/" + self.name + "_extra", "w") as f:
            for line in extra_ps:
                f.write(line)
        with open("./ps-Z-list/" + self.name + "_missing", "w") as f:
            for pkg in pkg_missing:
                f.write(pkg + "\n")
                
        #Dummy get PS
        self.device.shell("su -c \"ps -A -o label:40,UID:20,GID:20,PID,NAME:40 > /sdcard/ps\"")
        self.device.pull("sdcard/ps", "./ps-Z-list/" + self.name)
        self.device.shell("su -c \"rm /sdcard/ps\"")

    def get_ls(self):
        self.device.shell("su -c \"ls -alRZ > /sdcard/ls\"")
        self.device.pull("/sdcard/ls", "./ls_lRZ/" + self.name + "_raw")
        self.device.shell("su -c \"rm /sdcard/ls\"")
    
    def get_mac(self):
        self.device.shell("su -c \"cat /sys/fs/selinux/policy > /sdcard/sepolicy\"")
        self.device.pull("/sdcard/sepolicy", "./mac_policy/" + self.name + "_raw")
        self.device.shell("su -c \"rm /sdcard/sepolicy\"")
        
    def get_emulated(self):
        self.device.shell("su -c \"ls -alRZ /storage/emulated/0 > /sdcard/ls_emu\"")
        self.device.pull("/sdcard/ls_emu", "./ls_lRZ/" + self.name + "_raw_emu")
        self.device.shell("su -c \"rm /sdcard/ls_emu\"")

    def start_packages(self):
        self.device.shell("pm list packages -f", handler=self.handler)
        for line in self.package_list:
            fp = line[line.find("package:")+8:line.find(".apk")+4]
            folder = ""
            pkg_name = line[line.find(".apk")+5:]
            self.device.shell("am start " + pkg_name)

    def collect_data(self):
        print("Getting MAC Sepolicy file")
        self.get_mac()
        print("Getting ls")
        self.get_ls()
        self.get_emulated()
        print("Starting packages and getting ps")
        self.start_packages()
        self.advance_get_ps()
        print("Getting subgroup")
        self.get_subgroup()


#Data formatting
def get_mac(name):
    os.system("sesearch --allow ./mac_policy/" + name +  "_raw > ./mac_policy/" +name)

def get_attribute(name):
    os.system("seinfo -a -x ./mac_policy/" + name +  "_raw > ./attribute_file/" + name)
    file = open("./attribute_file/tmp", 'w')
    
    with open("./attribute_file/" + name) as f:
        for line in f:
            if line != "\n":
                file.write(line)
    
    os.system("mv ./attribute_file/tmp ./attribute_file/" + name)

def form_ls(name):
    wf = open("./ls_lRZ/" + name, 'w')
    wf1 = open("./ls_lRZ/" + name + "_emu", 'w')

    with open("./ls_lRZ/" + name + "_raw") as f:
        #Increase efficiency remove files only writable to root
        obj_name = "/"
        for line in f:
            if line.startswith("./"):
                if line.startswith("/:"):
                    obj_name = "/"
                else:
                    obj_name = line[1:-2] + "/"
            if line[0] == 'd' or line[0] == '-':
                if obj_name.startswith("/proc"):
                    continue
                cur_line = line.split()
                perm = cur_line[0]
                owner = cur_line[2]
                group = cur_line[3]

                if line[0] == '-' and owner == "root" and group == "root" and perm[8] != 'w':
                    #Increase efficiency remove files only writable to root
                    continue


                SE = cur_line[4]
                SEsplit = SE.split(":")
                label = SEsplit[2]
                
                cat = ""
                if len(SEsplit) > 4:
                    #Has Category
                    cat = SEsplit[4]
                if line.split()[8] == "." or line.split()[8] == "..":
                    continue
                full_path = obj_name + line.split()[8]
                if cat == "":
                    wf.write(perm + "  "+ owner + "  " + group + "  " + label + " " + full_path + "\n")
                else:
                    wf.write(perm + "  "+ owner + "  " + group + "  " + label + ":" + cat + " " + full_path+ "\n")
    
    with open("./ls_lRZ/" + name + "_raw_emu") as f:
        #Increase efficiency remove files only writable to root
        obj_name = ""
        for line in f:
            if line.startswith("/"):
                    obj_name = line[:-2] + "/"
            if line[0] == 'd' or line[0] == '-':
                if obj_name.startswith("/proc"):
                    continue
                cur_line = line.split()
                perm = cur_line[0]
                owner = cur_line[2]
                group = cur_line[3]

                if line[0] == '-' and owner == "root" and group == "root" and perm[8] != 'w':
                    #Increase efficiency remove files only writable to root
                    continue


                SE = cur_line[4]
                SEsplit = SE.split(":")
                label = SEsplit[2]
                cat = ""
                if len(SEsplit) > 4:
                    #Has Category
                    cat = SEsplit[4]
                full_path = obj_name + line.split()[8]

                if cat == "":
                    wf1.write(perm + "  "+ owner + "  " + group + "  " + label + " " + full_path + "\n")
                else:
                    wf1.write(perm + "  "+ owner + "  " + group + "  " + label + ":" + cat + " " + full_path+ "\n")
           
    wf.close()
    wf1.close()




if __name__ == "__main__":
    init_directories()
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", dest = "name", default = None,
						help = "Specify device name")
    parser.add_argument("-p", "--pull", dest = "pull", default = True, action='store_false',
                        help = "Dont pull apk files from device")
    
    args = parser.parse_args()
    device = args.name
    pull_apk = args.pull
    
    print("Data Collection Start: " + device)
    pull_apk_list(device)
    pull_pkg_list(device)
    
    #Only need to do this once, if dir exist don't do it
    if not os.path.isdir("./apks/" + device + "_app"):
        os.mkdir("./apks/" + device + "_app")
    
    if pull_apk:
        copy_apk_to_sdcard(device)
        pull_apk_files(device)

    get_manifest_file(device)  

    print("Finish Collecting and Parsing Apk Files-----")
    print("Start Collecting Data from Device-----")
    cur_phone = Phone(device)
    cur_phone.collect_data()

    print("Start Data Formatting-----")
    form_ls(device)
    get_mac(device)
    get_attribute(device)

	
