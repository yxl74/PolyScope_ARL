__author__  = "Eddy Lee"
__email__   = "yxl74@cse.psu.edu"
__copyright__ = "Copyright (C) 2020 PolyScope Project"
__license__   = "Public Domain"
__version__   = "6.0"
__date__      = "Dec 2021"

from helper import *
from time import process_time
import operator, sys, os, random
import argparse
import threading
import sqlite3
import xml.etree.ElementTree as ET
import multiprocessing as mp
import json, pickle
from tqdm import tqdm
from atpbar import register_reporter, find_reporter, flush, atpbar
from graph_lib import *
from ppadb.client import Client as AdbClient
from new_mac_module import MAC_TE



class Integrity_Violation:
    def __init__(self, attacker_pid, victim_pid, hash_value):
        self.att = attacker_pid
        self.vic = victim_pid
        self.hash_v = hash_value

    def __hash__(self):
        return hash(self.hash_v)

    def __eq__(self, other):
        return (self.hash_v == other.hash_v)

    def __ne__(self,other):
        return (self.hash_v != other.hash_v)


class Obj:
    def __init__(self, m_lable, owner, group, perms, filepath):
        self.MAC_label = m_lable
        self.owner = owner
        self.group = group
        self.perm = perms
        self.path = filepath

    def __hash__(self):
        return hash(self.path)

    def __eq__(self,other):
        
        if (self.MAC_label == other.MAC_label and self.owner == other.owner and self.group == other.group
                and self.perm == other.perm):
            #check path
            if (self.path.startswith("/data/data/") and other.path.startswith("/data/data/")):
                return True
            elif self.path.startswith("/storage/emulated/0/Android/data/") and other.path.startswith("/storage/emulated/0/Android/data/"):
                return True
            else:
                if self.path == other.path:
                    return True
            return False

    def __ne__(self,other):
        return not self.__eq__(other)


class Result:
    def __init__(self):
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.binding_lock = threading.Lock()
        self.pathname_lock = threading.Lock()
        self.result_lock = threading.Lock()

        self.read_IV = {}
        self.write_IV = {}
        self.binding_IV = {}
        self.pathname_IV = {}

#result class to carry data back from multi-process
class Result_p:
    def __init__(self):
        self.read_IV = {}
        self.write_IV = {}
        self.binding_IV = {}
        self.pathname_IV = {}

class Proc:
    def __init__(self):
        self.MAC_label = set()
        self.MLS = [] #Category only
        self.UID = set()
        self.GID = set()
        self.subgroup = set()
        self.PID = -1
        self.is_legacy = False
        self.is_Manager = False
        self.read_ext_storage = False
        self.useFProvider = False
        self.pkgname = ""

class Package:
    def __init__(self, pkgname):
        self.pkgname = pkgname
        self.subgroup = []
        self.uid = ""
        self.priv_level = ""
        self.mac_label_est = ""

class Polyscope:
    def __init__(self, name, target):
        #Cache for id number to name
        target_subject = target
        self.id_to_name = {}
        self.processes = {}  #PID --> proc
        self.apps = [] #Proc that are apps
        self.name = name
        self.legacy_pkgname = []
        self.manage_pkgname = []
        self.use_fileProvider_pkgname = []
        self.read_external_pkgname = []
        self.uid_to_pkgname = {}
        self.packages = []
        self.total_package = 0
        self.fail_mapping = 0
        self.all_pkgname = []
        
        #process classification
        self.p_class = {}
        #directory permissions
        self.dir_perms = {}

        #Start Initializing Polyscope Object
        print("Initializing Polyscope Object...")
        self.init_subgroup()
        print("Adding MAC Restriction to Analysis...")
        print("Adding DAC Restriction to Analysis...")
        print("Adding Android Permission Restriction to Analysis...")
        print("Adding Scoped Storage Restriction to Analysis...")
        self.init_dir_perms()
        #print("Parsing Manifest...")
        self.parse_manifest("./apks/" + self.name + "_apk_list")
        print("Parsing for UID to Pkgname Mapping...")
        self.parse_for_uid_to_pkgname("./db_file/" + self.name + "_pkglist")
        self.get_all_java("./apks/" + self.name + "_apk_list")
        self.parse_process_file("./ps-Z-list/" + self.name, True)

        print("Classifying Process Privilege Level...")
        self.process_classification()
        
        
        self.mac_analysis = MAC_TE(self.name)


    #Tool Function
    #Input: UserID in terms of ID
    #Output: UserID in terms of name
    def find_id_to_name(self, Id):
        client = client = AdbClient(host="127.0.0.1", port=5037)
        devices = client.devices()
        device = devices[0]
        gname = ""
        
        def handler1(connection):
            data = connection.read_all()
            data = data.decode('utf-8')
            nonlocal gname
            gname = data.split()[0]
            connection.close()

        device.shell("su -c \"id -nu " + Id + "\"", handler = handler1)
        return gname

    #Tool Function
    #Input: line
    #Output: Whether legacy flag is enable
    def check_legacy_flag(self,in_line):
        if "requestLegacyExternalStorage" in in_line and "true" in in_line:
            return True
        if "preserveLegacyStorage" in in_line and "true" in in_line:
            return True
        return False  

    def get_all_java(self, path):
        with open(path, 'r') as f:
            for line in f:
                fp = line[line.find("package:")+8:line.find(".apk")+4]
                folder = self.name + "_app"
                pkg_name = line[line.find(".apk")+5:-1]
                manifest_path = "./apks/" + folder + "/" + pkg_name + ".manifest"
                if os.path.exists(manifest_path):
                    self.all_pkgname.append(pkg_name)
                    
                        

    #Parse all manifest file
    #Input: Filepath to apk list file
    #Output: Data stored in internal map, in terms of pkgname
    def parse_manifest(self, fpath):
        with open(fpath, 'r') as f:
            for line in f:
                fp = line[line.find("package:")+8:line.find(".apk")+4]
                folder = self.name + "_app"
                pkg_name = line[line.find(".apk")+5:-1]
                self.total_package += 1
                manifest_path = "./apks/" + folder + "/" + pkg_name + ".manifest"
                if not os.path.exists(manifest_path):
                    continue
                
                file = open(manifest_path, 'r')
                for line in file:
                    if self.check_legacy_flag(line):
                        self.legacy_pkgname.append(pkg_name)
                    if "MANAGE_EXTERNAL_STORAGE" in line:
                        self.manage_pkgname.append(pkg_name)
                    if "FileProvider" in line:
                        self.use_fileProvider_pkgname.append(pkg_name)
                    if "READ_EXTERNAL_STROAGE" in line:
                        self.read_external_pkgname.append(pkg_name)
                    #Note write external storage is deprecated

    #Parse packages.list file managed by PackageManager
    def parse_for_uid_to_pkgname(self, fpath):
        with open(fpath, 'r') as f:
            for line in f:
                lst = line.split()
                pkg_name = lst[0]
                uid_raw = lst[1]
                
                
                #Store Potential Useful Data for Future use, subgroup, uid and priv_level 
                new_package = Package(pkg_name)
                
                if uid_raw not in self.id_to_name:
                    self.id_to_name[uid_raw] = self.find_id_to_name(lst[1])
                uid = self.id_to_name[uid_raw]
                if uid not in self.uid_to_pkgname:
                    self.uid_to_pkgname[uid] = set()
                self.uid_to_pkgname[uid].add(pkg_name)
                
                #Store Package subgroup, priv_level
                #network_stack:privapp --> priv_app
                #shared --> depends....(skip for now)
                #keyboard -- untrusted
                #release ----> skip these for now
                #platform:privapp --> platform_app
                #shared:priv_app --> privapp
                #default:priv_app --> privapp
                #default --> untrusted_app
                #samsung:privapp --> priv_app
                
                
                new_package.priv_level = ":".join(lst[4].split(":")[:-1])
                new_package.uid = uid
                
                #MAC label approximation
                if "privapp" in new_package.priv_level:
                    if "platform" in new_package.priv_level:
                        new_package.mac_label_est = "platform_app"
                    else:
                        new_package.mac_label_est = "priv_app"
                else:
                    if "default" in new_package.priv_level:
                        new_package.mac_label_est = "untrusted_app"
                    elif "keyboard" in new_package.priv_level:
                        new_package.mac_label_est = "untrusted_app"
                    else:
                        new_package.mac_label_est = "unknown/system"
                        #print(pkg_name)
                #if new_package.mac_label_est == "untrusted_app" and pkg_name not in self.all_pkgname:
                    #improve java percentage not include random untrusted_app without apk file
                    #continue


                
                #Obtain subgroup for future use
                if not lst[5] == "none":
                    for grp in lst[5].split(","):
                        if grp not in self.id_to_name:
                            self.id_to_name[grp] = self.find_id_to_name(grp)
                        new_package.subgroup.append(self.id_to_name[grp])
                
                self.packages.append(new_package)
                
                if not new_package.mac_label_est == "unknown/system":
                    new_proc = Proc()
                    new_proc.MAC_label = new_package.mac_label_est
                    new_proc.UID = new_package.uid
                    new_proc.GID = new_package.uid
                    new_proc.subgroup = new_package.subgroup
                    new_proc.pkgname = pkg_name
                    if new_proc.pkgname in self.legacy_pkgname:
                        new_proc.is_legacy = True
                    if new_proc.pkgname in self.manage_pkgname:
                        new_proc.is_Manager = True
                    if new_proc.pkgname in self.read_external_pkgname:
                        new_proc.read_ext_storage = True                        
                    if new_proc.pkgname in self.use_fileProvider_pkgname:
                        new_proc.useFProvider = True
                    fake_pid = str(random.randint(10000,20000))
                    while fake_pid in self.processes:
                        fake_pid = str(random.randint(10000,20000))
                    self.processes[fake_pid] = new_proc
                    
                    
        
    #Dynamic: Obtain subgroup data for each processes #
    def init_subgroup(self):
        subgroup = {}
        with open("./subgroup/" + self.name) as f:
            for line in f:
                if line.startswith("Name"):
                    continue
                else:
                    pid = line.split()[1]
                    line_split = line[line.find("Groups:")+8:]
                    if line_split != "":
                        pid = line.split()[1]
                        line_split = line[line.find("Groups:")+8:]
                        if line_split != "":
                            for sgid in line_split.split():
                                if sgid not in self.id_to_name:
                                    self.id_to_name[sgid] = self.find_id_to_name(sgid)
                                if pid in self.processes:
                                    self.processes[pid].subgroup.add(self.id_to_name[sgid])
            
            
        
    def parse_process_file(self, fpath, flag): 
        print("Parsing process file")
        with open(fpath, "r") as f:
            if flag:
                #Normal ps has title skip
                next(f)
            for line in f:
                new_proc = Proc()
                line_list = line.split()
                new_proc.MAC_label = line_list[0].split(":")[2]
                if len(line_list[0].split(":")) == 5:
                    #MLS cat available
                    mls_lst = line_list[0].split(":")[4].split(",")
                    for cat in mls_lst:
                        new_proc.MLS.append(cat)

                #Cache to not query through adb too many times
                if line_list[1] not in self.id_to_name:
                    self.id_to_name[line_list[1]] = self.find_id_to_name(line_list[1])
                if line_list[2] not in self.id_to_name:
                    self.id_to_name[line_list[2]] = self.find_id_to_name(line_list[2])
                
                #Assign UID/GID
                new_proc.UID = self.id_to_name[line_list[1]]
                new_proc.GID = self.id_to_name[line_list[2]]
                new_proc.PID = line_list[3]
                
                #PkgName, Could be corrupted/Not showing right value
                new_proc.pkgname = line_list[-1]
                #How do we know legacy info from here
                
                if new_proc.UID in self.uid_to_pkgname:
                    if new_proc.pkgname in self.uid_to_pkgname[new_proc.UID] or len(self.uid_to_pkgname[new_proc.UID]) == 1:
                        #correct UID-PkgName mapping or 1-1 mapping found
                        
                        #1-1 case
                        if len(self.uid_to_pkgname[new_proc.UID]) == 1 and new_proc.pkgname not in self.uid_to_pkgname[new_proc.UID]:
                            pkg = list(self.uid_to_pkgname[new_proc.UID])[0]
                            #if pkg != new_proc.pkgname:
                                #print(pkg, new_proc.pkgname)
                            new_proc.pkgname = pkg   
                        
                        if new_proc.pkgname in self.legacy_pkgname:
                            new_proc.is_legacy = True
                        if new_proc.pkgname in self.manage_pkgname:
                            new_proc.is_Manager = True
                        if new_proc.pkgname in self.read_external_pkgname:
                            new_proc.read_ext_storage = True
                        if new_proc.pkgname in self.use_fileProvider_pkgname:
                            new_proc.useFProvider = True
                    else:
                        #Incorrect PkgName, Perform Approximation of PkgName
                        #Do over-approximation, if one pkgname with same UID has legacy/manage
                        #give permission
                                      
                        for pkgname in self.uid_to_pkgname[new_proc.UID]:
                            if pkgname in self.legacy_pkgname:
                                new_proc.is_legacy = True
                            if pkgname in self.manage_pkgname:
                                new_proc.is_Manager = True
                            if pkgname in self.read_external_pkgname:
                                new_proc.read_ext_storage = True
                            if pkgname in self.use_fileProvider_pkgname:
                                new_proc.useFProvider = True
                        #change pkgname to approx to show it is approximated
                        new_proc.pkgname = "approx" 
                        #print(new_proc.UID, new_proc.MAC_label, new_proc.pkgname)
                
                #Finished populating new proc data
                self.processes[new_proc.PID] = new_proc

    #Classify Process by Google's definition
    def process_classification(self):
        
        def get_ps_MAC(line):
            return line.split()[0].split(":")[2]
        

        result = {}
        result["root"] = set()
        result["system"] = set()
        result["service"] = set()
        with open("./ps-Z-list/" + self.name) as f:
            next(f)
            for line in f:
                uid = self.find_id_to_name(line.split()[1])
                if uid == "root":
                    result["root"].add(get_ps_MAC(line))
                    #Add MAC Label
                elif uid == "system":
                    result["system"].add(get_ps_MAC(line))
                
                elif "app" in get_ps_MAC(line) and uid != "system":
                    #either plat_app, priv_app, untrusted_app
                    continue
                else:
                    #system_services
                    result["service"].add(get_ps_MAC(line))
        self.p_class = result

    #Get Priv Level of Process
    def get_priv_level(self, MAC_label):
        if MAC_label in self.p_class["root"]:
            return 5
        elif MAC_label in self.p_class["system"]:
            return 4 
        elif MAC_label in self.p_class["service"]:
            return 3
        else:
            if "priv_app" in MAC_label:
                return 2
            if "platform_app" in MAC_label:
                return 2
            return 1

    #Check whether its Inter-Level flow
    def check_attacker_victim_priv(self,attacker,victim, target):
        attacker_MAC = attacker.MAC_label
        victim_MAC = victim.MAC_label
        
        if victim.pkgname == target:
            if "untrusted_app" in attacker_MAC:
                return 10
        
        if (attacker_MAC in self.p_class["root"]):
                return -1
        if (attacker_MAC in self.p_class["system"]):
            if victim_MAC not in self.p_class["root"]:
                return -1
            else:
                return 9
        if (attacker_MAC in self.p_class["service"]):
            if victim_MAC in self.p_class["system"]:
                return 7
            if victim_MAC in self.p_class["root"]:
                return 8
            return -1
        if "platform_app" in attacker_MAC:
            if victim_MAC in self.p_class["system"]:
                return 5 
            if victim_MAC in self.p_class["root"]:
                return 6
            if victim_MAC in self.p_class["service"]:
                return 4
            return -1
        if "priv_app" in attacker_MAC:
            if victim_MAC in self.p_class["system"]:
                return 5 
            if victim_MAC in self.p_class["root"]:
                return 6
            if victim_MAC in self.p_class["service"]:
                return 4
        if "untrusted_app" in attacker_MAC:
            if victim_MAC in self.p_class["system"]:
                return 2 
            if victim_MAC in self.p_class["root"]:
                return 3
            if victim_MAC in self.p_class["service"]:
                return 1
            if "platform_app" or "priv_app" in victim_MAC:
                return 0
        
        return -1

    #Get directory permission
    def init_dir_perms(self):
        with open("./ls_lRZ/" + self.name, "r") as f:
            for line in f:
                if line[0] == 'd' and len(line.split()[0]) == 10:
                    self.dir_perms[line.split()[4]] = line.split()[0:3] 
        self.dir_perms["/storage/emulated/0"] = ["drwxrwx---", "root", "everybody", "fuse"]
        
        with open("./ls_lRZ/" + self.name + "_emu", "r") as f:
            for line in f:
                if line[0] == 'd' and len(line.split()[0]) == 10:
                    self.dir_perms[line.split()[4]] = line.split()[0:3]


    def check_file_reachability(self,pid, path):
        dirs = path.split("/")[1:-1] #eliminadef get_normal_perm(device):
        path_len = 0
        
        if(len(dirs) == 0): #root directory
            return True


        dir = ""

        while(path_len < len(dirs)):
            dir = dir + "/" + dirs[path_len]
            path_len += 1
            #Special Case for Pre-Scoped Storage
            if dir == "/mnt/runtime":
                continue
            #Subject equals to owner
            if (self.processes[pid].UID == self.dir_perms[dir][1])  and self.dir_perms[dir][0][3] == 'x':
                continue
            #Subject equals to group
            if (self.processes[pid].GID == self.dir_perms[dir][2] or self.dir_perms[dir][2] in self.processes[pid].subgroup) and self.dir_perms[dir][0][6] == 'x':
                continue
            #Subject equals any
            elif self.dir_perms[dir][0][9] == 'x':
                continue
            #Possible bug here
            return False
            
        return True

    def check_dir_writability(self,pid, path):
        dirs = path.split("/")[1:-1] #eliminadef get_normal_perm(device):
        path_len = 0

        uid = self.processes[pid].UID
        group = self.processes[pid].GID

        if(len(dirs) == 0):
            if uid == "root":
                return True
            if group == "root":
                return True
            return False
        dir = ""
        
        
        while(path_len < len(dirs)):
            dir = dir + "/" + dirs[path_len]
            path_len += 1
            if uid == self.dir_perms[dir][1] and self.dir_perms[dir][0][2] == 'w':
                return True
            if (group == self.dir_perms[dir][2] or self.dir_perms[dir][2] in self.processes[pid].subgroup) and self.dir_perms[dir][0][5] == 'w':
                return True
            elif self.dir_perms[dir][0][8] == 'w':
                return True

        return False

    def check_dac_writable(self, pid, owner, group, perms):
        if self.processes[pid].UID == owner and perms[2] == 'w':
            return True
        if (self.processes[pid].GID == group or group in self.processes[pid].subgroup) and perms[5] == 'w':
            return True
        if perms[8] == 'w':
            return True
        return False

    def check_dac_readable(self, pid, owner, group, perms):
        if self.processes[pid].UID == owner and perms[1] == 'r':
            return True
        if (self.processes[pid].GID == group or group in self.processes[pid].subgroup) and perms[4] == 'r':
            return True
        if perms[7] == 'r':
            return True
        return False
          
    #If random stats needed put code here
    def stats(self):
        print("Get Stats Here!")
        #count = 0
        #for uid in self.uid_to_pkgname:
        #   if len(self.uid_to_pkgname[uid]) != 1:
        #   print("Not One to One UID: " + uid)
        #   for pkgname in self.uid_to_pkgname[uid]:
        #   print(" " + pkgname)
        #   count += 1
        #   if pkgname in self.legacy_pkgname:
        #   print("   IS LEGACY")
        #print("Total Packages: " + str(self.total_package))
        #print("Shared Packages: " + str(count))
        
        
        #Grabbing process data




def multi_process_run(threadID, fset, analysis_obj, mp_queue, reporter, target):
    shared_folders = ["/storage/emulated/0/Alarms", "/storage/emulated/0/Audiobooks", 
                               "/storage/emulated/0/DCIM", "/storage/emulated/0/Documents", "/storage/emulated/0/Download", "/storage/emulated/0/Movies", 
                               "/storage/emulated/0/Music", "/storage/emulated/0/Notifications", "/storage/emulated/0/Pictures", 
                               "/storage/emulated/0/Podcasts", "/storage/emulated/0/Ringtones"]
    poly = analysis_obj
    result = Result_p()
    register_reporter(reporter)
    for line in atpbar(fset, name=("Proc" + str(threadID))):
        obj_label = get_dac_obj_label(line)
        if ":" in obj_label:
            obj_label = obj_label.split(":")[0]
        owner = get_dac_owner(line)
        group = get_dac_group(line)
        perms = get_dac_perms(line)
        filename = get_dac_filename(line)
        
        
        #For Speeding things up
        if filename.startswith("/mnt/runtime/default") or filename.startswith("/mnt/runtime/read"):
            continue
        if filename.startswith("/sys"):
            continue
        if filename.startswith("/proc"):
            continue
        if filename.startswith("/dev"):
            continue
        #write only Android Filesystem
        if filename.startswith("/system"):
            continue
        
        
        if filename.startswith("/proc") or filename.startswith("/system") or filename.startswith("/dev") or filename.startswith("/sys"):
            continue
        #if perms.startswith("d"):
            #continue

        #File writer under DAC, contains proc PID
        file_writer = set()
        file_reader = set()
        dir_writer = set()
        
        mac_reader = set()
        file_owner = set()
        
        for pid in poly.processes:
            cur_proc = poly.processes[pid]
            if "magisk" in cur_proc.MAC_label:
                continue
            
            #if scoped storage special case:
            #Special Cases for Scoped Storage
            #if filename.startswith("/storage/emulated/0") and not filename.startswith("/storage/emulated/0/Android/media") and not filename.startswith("/storage/emulated/0/Android/obb"):
            if filename.startswith("/storage/emulated/0"):
                in_shared = False
                in_app_specific = False
                for folder_name in shared_folders:
                    if filename.startswith(folder_name):
                        in_shared = True
                if filename.startswith("/storage/emulated/0/Android/data"):
                    in_app_specific = True
                    
                #if media_rw, sdcard_rw, access to everything
                #if "sdcard_rw" in cur_proc.subgroup or "media_rw" in cur_proc.subgroup:
                if "sdcard_rw" in cur_proc.subgroup or "media_rw" in cur_proc.subgroup:
                    file_writer.add(pid)
                    file_reader.add(pid)
                    dir_writer.add(pid)
                    #print(cur_proc.UID)
                                       
                else:
                    if in_shared:
                        #Case in-shared folder
                        #Writable by file owner, legacy app, manage_all_file app
                        if cur_proc.is_Manager:
                            file_writer.add(pid)
                            dir_writer.add(pid)
                        #Add if owner then write
                        #Given read_external_storage can read
                        file_reader.add(pid)
                    elif in_app_specific:
                        #in app-specific just go with DAC
                        if cur_proc.UID == owner:
                            file_writer.add(pid)
                            dir_writer.add(pid)
                    else:
                        #Legacy app full read/write access
                        #To shared folder
                        if cur_proc.is_Manager or cur_proc.is_legacy:
                            file_writer.add(pid)
                            dir_writer.add(pid)
                            file_reader.add(pid)
            else:         
                #check Dir Reachability
                c1 = poly.check_file_reachability(pid, filename)

                #Check MAC Writability
                c2 = (obj_label in poly.mac_analysis.subj_write_file[cur_proc.MAC_label])

                #Check MAC Readability
                c3 = (obj_label in poly.mac_analysis.subj_read_file[cur_proc.MAC_label])

                #Check MAC Dir Writability
                c4 = (obj_label in poly.mac_analysis.subj_write_dir[cur_proc.MAC_label])

                #Check DAC Writability
                c5 = poly.check_dac_writable(pid, owner, group, perms)

                #Check DAC Readability
                c6 = poly.check_dac_readable(pid, owner, group, perms)

                #Check DAC Dir Writability
                c7 = poly.check_dir_writability(pid,filename)

                
                if c1 and c2 and c5:
                    file_writer.add(pid)
            
                if c1 and c3 and c6:
                    file_reader.add(pid)

                if c1 and c4 and c7:
                    dir_writer.add(pid)
                    file_writer.add(pid)

                if c1 and c2 and cur_proc.UID == owner:
                    file_owner.add(pid)

                if c3:
                    mac_reader.add(pid)

            for v_pid in file_reader:
                for a_pid in file_writer:
                    attacker_proc = poly.processes[a_pid]
                    victim_proc = poly.processes[v_pid]

                    
                    if target != "None" and attacker_proc.pkgname != target and victim_proc.pkgname != target:
                        continue 

                    
                    #If attacker is in victim's TCB continue, not an IV
                    if attacker_proc.MAC_label in poly.mac_analysis.integrity_wall[victim_proc.MAC_label] or \
                        attacker_proc.MAC_label in poly.mac_analysis.TCB:
                        continue


                    cross_priv = poly.check_attacker_victim_priv(attacker_proc, victim_proc, target)
                    
                    #Not inter-level or Attacker more privilege than victim
                    if cross_priv == -1:
                        continue

                    #Found Integrity Violation, Need to classify
                    obj = Obj(obj_label, owner, group, perms, filename)
                    hash_value = attacker_proc.MAC_label + attacker_proc.UID + attacker_proc.GID + victim_proc.MAC_label + victim_proc.UID + victim_proc.GID
                    iv = Integrity_Violation(a_pid, v_pid, hash_value)


                    #Read-IV
                    if obj not in result.read_IV:
                        result.read_IV[obj] = set()
                    result.read_IV[obj].add(iv)


                    #Write-IV
                    if v_pid in file_writer:
                        #victim can also write
                        
                        if obj not in result.write_IV:
                            result.write_IV[obj] = set()
                        result.write_IV[obj].add(iv)
              
                    #Binding-IV
                    if a_pid in dir_writer:

                        if obj not in result.binding_IV:
                            result.binding_IV[obj] = set()
                        result.binding_IV[obj].add(iv)
                    



            #DAC-Expansion
            for v_pid in mac_reader:    
                for a_pid in file_owner:
                    attacker_proc = poly.processes[a_pid]
                    victim_proc = poly.processes[v_pid]

                    #If attacker is in victim's TCB continue, not an IV
                    if attacker_proc.MAC_label in poly.mac_analysis.integrity_wall[victim_proc.MAC_label] or \
                        attacker_proc.MAC_label in poly.mac_analysis.TCB:
                        continue
                    
                    cross_priv = poly.check_attacker_victim_priv(attacker_proc, victim_proc, target)
                    if cross_priv == -1:
                        continue


                    #Found possible Pathname-IV (DAC-Expansion)
                    obj = Obj(obj_label, owner, group, perms, filename)
                    hash_value = attacker_proc.MAC_label + attacker_proc.UID + attacker_proc.GID + victim_proc.MAC_label + victim_proc.UID + victim_proc.GID
                    iv = Integrity_Violation(a_pid, v_pid,hash_value)

                    

                    if obj not in result.pathname_IV:
                        result.pathname_IV[obj] = set()
                    result.pathname_IV[obj].add(iv)
    mp_queue.put(result)
    return

def compress_path(path):
    dir = path.split("/")[1:-1]
    if path.startswith("/storage/emulated/0/oem_log"):
        return "/".join(dir[1:5])
    Pdir = "/".join(dir)
    return Pdir

def compress_path1(path):
    dir = path.split("/")[1:-2]
    if path.startswith("/storage/emulated/0/oem_log"):
        return "/".join(dir[1:5])
    Pdir = "/".join(dir)
    return Pdir

def location(path):
    shared_folders = ["/storage/emulated/0/Alarms", "/storage/emulated/0/Audiobooks", 
                               "/storage/emulated/0/DCIM", "/storage/emulated/0/Documents", "/storage/emulated/0/Download", "/storage/emulated/0/Movies", 
                               "/storage/emulated/0/Music", "/storage/emulated/0/Notifications", "/storage/emulated/0/Pictures", 
                               "/storage/emulated/0/Podcasts", "/storage/emulated/0/Ringtones"]
    in_shared = False
    in_app_specific = False
    for folder_name in shared_folders:
        if path.startswith(folder_name):
            in_shared = True
        if path.startswith("/storage/emulated/0/Android/data"):
            in_app_specific = True
    if in_shared:
        return 1
    elif in_app_specific:
        return 2
    else:
        return 3

def write_result(result, poly, name, target):
    if not os.path.isdir("./dac_result/" + name):
        os.mkdir("./dac_result/" + name)

    read_iv_f = open("./dac_result/" + name + "/read_IV", "w")
    write_iv_f = open("./dac_result/" + name + "/write_IV", "w")
    binding_iv_f = open("./dac_result/" + name + "/binding_IV", "w")
    pathname_iv_f = open("./dac_result/" + name + "/pathname_IV", "w")

    all_package_name_f = open("./dac_result/" + name + "/all_package_name", "w")
    java_package_name_f = open("./dac_result/" + name + "/java_package_name", "w")

    read_iv_count = set()
    write_iv_count = set()
    binding_count = set()
    pathname_count = set()

    total_process_count = set()
    
    file_op = set()
    squat_op = set()
    pathname_op = set()
    
    ext_file_op_legacy = set()
    ext_binding_op_legacy = set()
    
    
    ext_vic_legacy = set()
    ext_obj_legacy = set()
    
    
    ext_file_op_scoped = set()
    ext_binding_op_scoped = set()
    
    ext_vic_scoped = set()
    ext_obj_scoped = set()
    
    scoped_app_count = set()
    legacy_app_count = set()

    legacy_attacker_count = set()
    legacy_victim_count = set()
    
    total_attacker_count = set()
    total_victim_count = set()
    total_object_count = set()
    
    scoped_attacker_count = set()
    scoped_victim_count = set()
    
    v_target_file_obj = set()
    v_target_binding_obj = set()
    v_target_pathname_obj = set()

    binding_json = {}
    file_json = {}
    pathname_json = {}

    def get_dir(inPath):
        tmp = inPath.split("/")[0:-1]
        return "/".join(tmp)
        
    #Do object/subject count
    


    for obj in result.read_IV:
        read_iv_f.write("***" + obj.path + "***" + obj.MAC_label + " "  +obj.owner + " " + obj.group + " " + obj.perm + "\n")
        for iv in result.read_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            #if "sdcard_rw" in vic.subgroup or "media_rw" in vic.subgroup:
                #continue
            obj_adder = (obj.MAC_label + " " + compress_path(obj.path) + " " + obj.owner + " " + obj.group + " " + obj.perm)
            vic_adder = vic.MAC_label + " " + vic.pkgname + " " + vic.UID + " " + vic.GID
            att_adder = att.MAC_label + " " + att.pkgname + " " + att.UID + " " + att.GID
            count_adder = vic_adder + obj_adder
            read_iv_count.add(count_adder)
            read_iv_f.write("   "+ iv.att + " "  + att.MAC_label + " " + att.UID + " " + att.GID + "***" + iv.vic + " "  +vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")
            
            
            #Attack Graph Stuff HERE
            total_process_count.add(iv.att)
            total_process_count.add(iv.vic)
            
            total_attacker_count.add(att_adder)
            total_victim_count.add(vic_adder)
            total_object_count.add(obj_adder)
            file_op.add(count_adder)

            if obj_adder not in file_json:
                file_json[obj_adder] = set()
            
            file_json[obj_adder].add((att_adder, vic_adder))
            
            
            if vic.pkgname == target:
                v_target_file_obj.add(obj_adder)
            
            
            if "app" in att.MAC_label:
                if att.is_legacy:
                    legacy_victim_count.add(vic_adder)
                    legacy_app_count.add(iv.att)
                else:
                    scoped_victim_count.add(vic_adder)
                    scoped_app_count.add(iv.att)
            if "app" in vic.MAC_label:
                if vic.is_legacy:
                    legacy_attacker_count.add(att_adder)
                    legacy_app_count.add(iv.vic)
                else:
                    scoped_attacker_count.add(att_adder)
                    scoped_app_count.add(iv.vic)
            
            if location(obj.path) == 3:
                ext_file_op_legacy.add(count_adder)
                ext_vic_legacy.add(vic_adder)
                ext_obj_legacy.add(obj_adder)
            else:
                ext_file_op_scoped.add(count_adder)
                ext_vic_scoped.add(vic_adder)
                ext_obj_scoped.add(obj_adder)

    for obj in result.write_IV:
        write_iv_f.write("***" + obj.path + "***" + obj.MAC_label + " "  +obj.owner + " " + obj.group + " " + obj.perm + "\n")
        for iv in result.write_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            #if "sdcard_rw" in vic.subgroup or "media_rw" in vic.subgroup:
                #continue
            obj_adder = (obj.MAC_label + " " + compress_path(obj.path) + " " + obj.owner + " " + obj.group + " " + obj.perm)
            vic_adder = vic.MAC_label + " " + vic.pkgname + " " + vic.UID + " " + vic.GID
            att_adder = att.MAC_label + " " + att.pkgname + " " + att.UID + " " + att.GID
            count_adder = vic_adder + obj_adder
            write_iv_count.add(count_adder)
            total_attacker_count.add(att_adder)
            total_victim_count.add(vic_adder)
            total_object_count.add(obj_adder)
            file_op.add(count_adder)
            
            #Attack Graph Stuff HERE
            total_process_count.add(iv.att)
            total_process_count.add(iv.vic)
            
            if obj_adder not in file_json:
                file_json[obj_adder] = set()
            
            file_json[obj_adder].add((att_adder, vic_adder))
            
            if vic.pkgname == target:
                v_target_file_obj.add(obj_adder)
            
            if "app" in att.MAC_label:
                if att.is_legacy:
                    legacy_victim_count.add(vic_adder)
                    legacy_app_count.add(iv.att)
                else:
                    scoped_victim_count.add(vic_adder)
                    scoped_app_count.add(iv.att)
            if "app" in vic.MAC_label:
                if vic.is_legacy:
                    legacy_attacker_count.add(att_adder)
                    legacy_app_count.add(iv.vic)
                else:
                    scoped_attacker_count.add(att_adder)
                    scoped_app_count.add(iv.vic)
                  
            if location(obj.path)==3:
                ext_file_op_legacy.add(count_adder)
                ext_vic_legacy.add(vic_adder)
                ext_obj_legacy.add(obj_adder)
            else:
                ext_file_op_scoped.add(count_adder)
                ext_vic_scoped.add(vic_adder)
                ext_obj_scoped.add(obj_adder)
            write_iv_f.write("   "+ iv.att + " "  + att.MAC_label + " " + att.UID + " " + att.GID + "***" + iv.vic + " "  +vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")

    for obj in result.binding_IV:
        binding_iv_f.write("***" + obj.path + "***" + obj.MAC_label + " "  +obj.owner + " " + obj.group + " " + obj.perm + "\n")
        for iv in result.binding_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            #if "sdcard_rw" in vic.subgroup or "media_rw" in vic.subgroup:
                #continue
            obj_adder = (obj.MAC_label + " " + compress_path(obj.path) + " " + obj.owner + " " + obj.group + " " + obj.perm)
            vic_adder = vic.MAC_label + " " + vic.pkgname + " " + vic.UID + " " + vic.GID
            att_adder = att.MAC_label + " " + att.pkgname + " " + att.UID + " " + att.GID
            count_adder = vic_adder + obj_adder
            binding_count.add(count_adder)
            total_attacker_count.add(att_adder)
            total_victim_count.add(vic_adder)
            total_object_count.add(obj_adder)
            
            #Attack Graph Stuff HERE
            total_process_count.add(iv.att)
            total_process_count.add(iv.vic)
            
            
            if vic.read_ext_storage or vic.is_Manager or vic.is_legacy or ("sdcard_rw" in vic.subgroup or "media_rw" in vic.subgroup):
                squat_op.add(count_adder)
            else:
                pathname_op.add(count_adder)
                
            if vic.pkgname == target:
                v_target_binding_obj.add(obj_adder)

            if obj_adder not in binding_json:
                binding_json[obj_adder] = set()
            binding_json[obj_adder].add((att_adder, vic_adder))
            
            
            if "app" in att.MAC_label:
                if att.is_legacy:
                    legacy_victim_count.add(vic_adder)
                    legacy_app_count.add(iv.att)
                else:
                    scoped_victim_count.add(vic_adder)
                    scoped_app_count.add(iv.att)
            if "app" in vic.MAC_label:
                if vic.is_legacy:
                    legacy_attacker_count.add(att_adder)
                    legacy_app_count.add(iv.vic)
                else:
                    scoped_attacker_count.add(att_adder)
                    scoped_app_count.add(iv.vic)

            if location(obj.path)==3:
                ext_binding_op_legacy.add(count_adder)
                ext_vic_legacy.add(vic_adder)
                ext_obj_legacy.add(obj_adder)
            else:
                ext_binding_op_scoped.add(count_adder)
                ext_vic_scoped.add(vic_adder)
                ext_obj_scoped.add(obj_adder)
            binding_iv_f.write("   "+ iv.att + " "  + att.MAC_label + " " + att.UID + " " + att.GID + "***" + iv.vic + " "  +vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")

    for obj in result.pathname_IV:
        pathname_iv_f.write("***" + obj.path + "***" + obj.MAC_label + " "  +obj.owner + " " + obj.group + " " + obj.perm + "\n")
        for iv in result.pathname_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            att_adder = att.MAC_label + " " + att.pkgname + " " + att.UID + " " + att.GID
            obj_adder = (obj.MAC_label + " " + compress_path(obj.path) + " " + obj.owner + " " + obj.group + " " + obj.perm)
            vic_adder = vic.MAC_label + " " + vic.pkgname + " " + vic.UID + " " + vic.GID
            count_adder = vic_adder + obj_adder
            pathname_count.add(count_adder)
            pathname_iv_f.write("   "+ iv.att + " "  + att.MAC_label + " " + att.UID + " " + att.GID + "***" + iv.vic + " "  +vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")
            total_attacker_count.add(att_adder)
            total_victim_count.add(vic_adder)
            total_object_count.add(obj_adder)
            
            #Attack Graph Stuff HERE
            total_process_count.add(iv.att)
            total_process_count.add(iv.vic)
            
            
            
            if obj_adder not in pathname_json:
                pathname_json[obj_adder] = set()
            
            pathname_json[obj_adder].add((att_adder, vic_adder))


            
            if vic.pkgname == target:
                v_target_pathname_obj.add(obj_adder)
            
            
            if "app" in att.MAC_label:
                if att.is_legacy:
                    legacy_victim_count.add(vic_adder)
                    legacy_app_count.add(iv.att)
                else:
                    scoped_victim_count.add(vic_adder)
                    scoped_app_count.add(iv.att)
            if "app" in vic.MAC_label:
                if vic.is_legacy:
                    legacy_attacker_count.add(att_adder)
                    legacy_app_count.add(iv.vic)
                else:
                    scoped_attacker_count.add(att_adder)
                    scoped_app_count.add(iv.vic)



    if target == "None":
        print("Total Subject-Count: " + str(len(total_process_count)))
        java_count = 0
        for proc in total_process_count:
            cur_proc = poly.processes[proc]
            all_package_name_f.write(cur_proc.pkgname + "\n")
        for proc in total_process_count:
            cur_proc = poly.processes[proc]
            if cur_proc.pkgname in poly.all_pkgname:
                java_count += 1
                java_package_name_f.write(cur_proc.pkgname + "\n")
            #else:
                #print(cur_proc.pkgname, cur_proc.UID, cur_proc.GID, cur_proc.MAC_label)

        
    else:
        print("Outputing Analysis Result for " + target + "...")
        print("File-IV-object: ", len(v_target_file_obj))
        print("Binding-IV-object: ", len(v_target_binding_obj))
        print("Pathname-IV-object: ", len(v_target_pathname_obj))
        
        t1 = open("./dac_result/" + name  +"/v_target_file_obj", "w")
        t2 = open("./dac_result/" + name  +"/v_target_binding_obj", "w")
        t3 = open("./dac_result/" + name  +"/v_target_pathname_obj", "w")
        
        t4 = open("./dac_result/" + name  +"/binding_op", "w")
        t5 = open("./dac_result/" + name  +"/pathname_op", "w")
        t6 = open("./dac_result/" + name  +"/file_op", "w")
        #t7 = open("./dac_result/" + name  +"/traversal_op.json", "w")
        
        for obj in v_target_file_obj:
            t1.write(obj + "\n")
        for obj in v_target_binding_obj:
            t2.write(obj + "\n")
        for obj in v_target_pathname_obj:
            t3.write(obj + "\n")
        
        for obj in binding_json:
            lst = list(binding_json[obj])
            binding_json[obj] = lst
        
        for obj in pathname_json:
            lst = list(pathname_json[obj])
            pathname_json[obj] = lst
        
        for obj in file_json:
            lst = list(file_json[obj])
            file_json[obj] = lst

        
        json.dump( binding_json, t4 )
        json.dump( pathname_json, t5 )
        json.dump( file_json, t6 )
        #json.dump( result.traversal_IV, t7 )


    
def cross_priv_helper(poly, attacker, victim):
    a_priv = poly.get_priv_level(attacker)
    v_priv = poly.get_priv_level(victim)
    
    if a_priv == 1:
        if v_priv == 2:
            return 0
        if v_priv == 3:
            return 1
        if v_priv == 4:
            return 2
        if v_priv == 5:
            return 3
    elif a_priv == 2:
        if v_priv == 3:
            return 4
        if v_priv == 4:
            return 5
        if v_priv == 5:
            return 6
    elif a_priv == 3:
        if v_priv == 4:
            return 7
        if v_priv == 5:
            return 8
    elif a_priv == 4:
        if v_priv == 5:
            return 9
    return -1

def cross_priv_stats(result,poly,name):
    #Get cross priv level count
    cross_priv = []
    for i in range(10):
        cross_priv.append(set())  
    #lv1_to_lv2 1
    #lv1_to_lv3 2
    #lv1_to_lv4 3
    #lv1_to_lv5 4
    #lv2_to_lv3 5
    #lv2_to_lv4 6
    #lv2_to_lv5 7
    #lv3_to_lv4 8
    #lv3_to_lv5 9
    #lv4_to_lv5 10
    
    for obj in result.read_IV:
        for iv in result.read_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            adder = (att.MAC_label + " " + att.UID + " " + att.GID + " " + vic.MAC_label + " " + vic.UID + " " + vic.GID)
            cross_priv[cross_priv_helper(poly, att.MAC_label, vic.MAC_label)].add(adder)
    
    for obj in result.write_IV:
        for iv in result.write_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            adder = (att.MAC_label + " " + att.UID + " " + att.GID + " " + vic.MAC_label + " " + vic.UID + " " + vic.GID)
            cross_priv[cross_priv_helper(poly, att.MAC_label, vic.MAC_label)].add(adder)
    
    for obj in result.binding_IV:
        for iv in result.binding_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            adder = (att.MAC_label + " " + att.UID + " " + att.GID + " " + vic.MAC_label + " " + vic.UID + " " + vic.GID)
            cross_priv[cross_priv_helper(poly, att.MAC_label, vic.MAC_label)].add(adder)

    for obj in result.pathname_IV:
        for iv in result.pathname_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            adder = (att.MAC_label + " " + att.UID + " " + att.GID + " " + vic.MAC_label + " " + vic.UID + " " + vic.GID)
            cross_priv[cross_priv_helper(poly, att.MAC_label, vic.MAC_label)].add(adder)
    
    cross_priv_file = open("./dac_result/" + name + "/cross_priv_count", "w")
    cur_floor = 1
    i = 1
    j = 2
    for obj_set in cross_priv:
        cross_priv_file.write("level "+ str(i) + " to level " + str(j) + ":" + str(len(obj_set)) + "\n")
        i += 1
        j += 1
        if j == 6:
            i = cur_floor + 1
            cur_floor += 1
            j = i+1        
    
def generate_attack_graph(result, poly, name):
    normal_graph = Attack_Graph()
    subj_to_subj = Attack_Graph()
    attack_op = Attack_Graph()

    for obj in result.read_IV:
        normal_graph.add_node(obj.path, "file", "obj")
        for iv in result.read_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            att_label = att.MAC_label + " " + att.UID + " " + att.GID
            vic_label = vic.MAC_label + " " + vic.UID + " " + vic.GID
            
            normal_graph.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            normal_graph.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            subj_to_subj.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            subj_to_subj.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            normal_graph.add_edge(att_label, obj.path, 1)
            normal_graph.add_edge(obj.path, vic_label, 1)
            subj_to_subj.add_edge(att_label, vic_label, 1)
        
    for obj in result.write_IV:
        normal_graph.add_node(obj.path, "file", "obj")
        for iv in result.write_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            att_label = att.MAC_label + " " + att.UID + " " + att.GID
            vic_label = vic.MAC_label + " " + vic.UID + " " + vic.GID
            
            normal_graph.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            normal_graph.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            subj_to_subj.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            subj_to_subj.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            normal_graph.add_edge(att_label, obj.path, 1)
            normal_graph.add_edge(obj.path, vic_label, 1)
            subj_to_subj.add_edge(att_label, vic_label, 1)
    
    for obj in result.binding_IV:
        normal_graph.add_node(obj.path, "file", "obj")
        for iv in result.binding_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            att_label = att.MAC_label + " " + att.UID + " " + att.GID
            vic_label = vic.MAC_label + " " + vic.UID + " " + vic.GID
            
            normal_graph.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            normal_graph.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            subj_to_subj.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            subj_to_subj.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            normal_graph.add_edge(att_label, obj.path, 1)
            normal_graph.add_edge(obj.path, vic_label, 1)
            subj_to_subj.add_edge(att_label, vic_label, 1)

    for obj in result.pathname_IV:
        normal_graph.add_node(obj.path, "file", "obj")
        for iv in result.binding_IV[obj]:
            att = poly.processes[iv.att]
            vic = poly.processes[iv.vic]
            att_label = att.MAC_label + " " + att.UID + " " + att.GID
            vic_label = vic.MAC_label + " " + vic.UID + " " + vic.GID
            
            normal_graph.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            normal_graph.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            subj_to_subj.add_node(att_label, poly.get_priv_level(att.MAC_label), "subj")
            subj_to_subj.add_node(vic_label, poly.get_priv_level(vic.MAC_label), "subj")

            normal_graph.add_edge(att_label, obj.path, 1)
            normal_graph.add_edge(obj.path, vic_label, 1)
            subj_to_subj.add_edge(att_label, vic_label, 1)
    normal_graph.write_graph("./dac_result/" + name + "/att_graph")
    subj_to_subj.write_graph("./dac_result/" + name + "/subj_graph")





            
            
            
            
        

def combine(qout, poly, target):
    final_result = Result_p()
    print("Data Combine Start")
    #Produce stats too, need victim subject #, object #
    total_vic_count = set()
    total_object_count = set()
        
    write_IV_vic_count = set()
    read_IV_vic_count = set()
    binding_IV_vic_count = set()
    pathname_IV_vic_count = set()
        
    write_IV_obj_count = set()
    read_IV_obj_count = set()
    binding_IV_obj_count = set()
    pathname_IV_obj_count = set()
    
    
    
        
    for t_result in qout:
        #bunch of result need to combine
        for obj in t_result.write_IV:
            if obj not in final_result.write_IV:
                final_result.write_IV[obj] = set()
            total_object_count.add(obj)
            write_IV_obj_count.add(obj)
            
            for iv in t_result.write_IV[obj]:
                final_result.write_IV[obj].add(iv)
                write_IV_vic_count.add(poly.processes[iv.vic])
                total_vic_count.add(poly.processes[iv.vic])
                    

        for obj in t_result.read_IV:
            if obj not in final_result.read_IV:
                final_result.read_IV[obj] = set()
            total_object_count.add(obj)
            read_IV_obj_count.add(obj)
            
            for iv in t_result.read_IV[obj]:
                final_result.read_IV[obj].add(iv)
                read_IV_vic_count.add(poly.processes[iv.vic])
                total_vic_count.add(poly.processes[iv.vic])
        
        for obj in t_result.binding_IV:
            if obj not in final_result.binding_IV:
                final_result.binding_IV[obj] = set()
            total_object_count.add(obj)
            binding_IV_obj_count.add(obj)
            
            for iv in t_result.binding_IV[obj]:
                final_result.binding_IV[obj].add(iv)
                binding_IV_vic_count.add(poly.processes[iv.vic])
                total_vic_count.add(poly.processes[iv.vic])
        
        for obj in t_result.pathname_IV:
            if obj not in final_result.pathname_IV:
                final_result.pathname_IV[obj] = set()
            total_object_count.add(obj)
            pathname_IV_obj_count.add(obj)
            for iv in t_result.pathname_IV[obj]:
                final_result.pathname_IV[obj].add(iv)
                pathname_IV_vic_count.add(poly.processes[iv.vic])
                total_vic_count.add(poly.processes[iv.vic])
    
    
    if target == "None":
        print("Total Victim Subject Count: ", len(total_vic_count))
        print("-----------------------------------------------------------")
        print("Write-IV victim Subject Count: ", len(write_IV_vic_count))
        print("Read-IV victim subject count: ", len(read_IV_vic_count))
        print("Binding-IV victim subject count: ", len(binding_IV_vic_count))
        print("Pathname-IV victim subject count: ", len(pathname_IV_vic_count))
    
        print("Total Object Count: ", len(total_object_count))
        print("-----------------------------------------------------------")
        print("Write-IV object Count: ", len(write_IV_obj_count))
        print("Read-IV object count: ", len(read_IV_obj_count))
        print("Binding-IV object count: ", len(binding_IV_obj_count))
        print("Pathname-IV object count: ", len(pathname_IV_obj_count))
    
        print(len(final_result.read_IV))
        print(len(final_result.write_IV))   
    return final_result
        
            
        

if __name__ == "__main__":
    t1_start = process_time()
    parser = argparse.ArgumentParser()
        
    parser.add_argument("-n", "--name", dest = "name", default = None,
                        help = "Specify device name")
    parser.add_argument("-p", "--proc", dest = "proc", default = None, 
                        help = "Number of Process")
    parser.add_argument("-s", "--scoped", action='store_false' ,dest= "scope", default = True,
                        help = "Scoped or not")
    parser.add_argument("-t", "--target", dest = "target", default = "None", 
                        help = "target specific subject o study")
        
    args = parser.parse_args()
    device_name = args.name
    p_count = int(args.proc)
    scoped = args.scope
    target = args.target
    
    if target != "None":
        print("Analyzing Targeted Subject with PkgName: " + target)
    
        
    polyscope = Polyscope(device_name, target)
    result = Result()
        
    ftotal = []
    fset_map = {}

    with open("./ls_lRZ/" + args.name + "_emu", "r") as f:
        for line in f:
            ftotal.append(line)
    #with open("./ls_lRZ/" + args.name, "r") as f:
        #for line in f:
            #ftotal.append(line)

    for i in range(p_count):
        random.shuffle(ftotal)
    
    split = len(ftotal)//p_count + 1
    k = 0
    for i in range(p_count):
        fset_map[i] = []
    for line in ftotal:
        fset_map[k].append(line)
        k += 1
        if k == p_count:
            k = 0

    print("Starting Worker Thread")
    #thread_pool = []
    #for m in range(p_count):
    #   t = Run_analysis(m, fset_map[m] , polyscope, result)
    #   thread_pool.append(t)
    #   t.start()
    #for trd in thread_pool:
    #   trd.join()
    proc_pool = []
    f_results = []
    qout = mp.Queue()
    reporter = find_reporter()
    for m in range(p_count):
        new_proc = mp.Process(target = multi_process_run, args=(m,fset_map[m], polyscope, qout,reporter, target))
        proc_pool.append(new_proc)
    
    for p in proc_pool:
        p.start()

    
    
    while 1:
        running = any(p.is_alive() for p in proc_pool)
        while not qout.empty():
            f_results.append(qout.get())
        if not running:
            break
    flush()

        
    final_result = combine(f_results, polyscope, target)
    print("Analysis Complete, data ouput")
    write_result(final_result, polyscope, args.name, target)
    #cross_priv_stats(final_result,polyscope,args.name)
        
        
    t1_stop = process_time()
    print("Total Time: ", t1_stop-t1_start)    
        
    #Should have result now
    #write_result(result, polyscope, args.name)  
        
        
        
        
