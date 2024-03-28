# PolyScope_Scoped
,,,
sudo apt install python3
pip3 install pure-python-adb
pip3 install atpbar
sudo apt-get install -y setools
,,,
Need to install apkanalyzer through AndroidStudio and add it into terminal PATH


Running PolyScope python Scripts:

Pre-Condition for Data Collection:
Rooted / Magisk installed, remember to grant shell root permission

Data Collection:
(with phone connected, adb available, and atak app installed)
python3 dataCollection.py -n <device_name> 

Name device name by yourself

Running PolyScope:
python3 scopedStorage_polyscope.py -n <device_name> -p <thread_number> -t <target_pakage_name>

So to run with atak, it would be:
python3 scopedStorage_polyscope.py -n oneplus8T_12 -p 8 -t com.atakmap.app.civ


Results:
Located in dac_result/<device_name>
Binding-IV, File-IV, Pathname-IV shown in terms of 

***<object path> *** <MAC_label> *** <owner UID> *** <GID> *** <perm>

Followed by  <attacker> *** <victim>
Both in form <PID> <MAC_label> <UID> <GID>



Additionally, there are three files, v_target_binding_obj, v_target_file_obj, v_target_pathname_obj

Which corresponds to vulnerable object (file/dir)that could be used to launch an attack.

