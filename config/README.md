# Config Files
The following attributes have to be added to the respective configuration files

## Individual Configuration file `misc_config.py`

* `ENABLE_EXTRACT_SOURCES` - Boolean, `True`: Enable extracting and decompiling sources (lowers performance) from the `classes.dex` file
* `ENABLE_ZIPFILE_HASHING` - Boolean, `True`: Enable hashing (md5, sha1, sha256) all files inside an application (APK/ZIP)
* `ENABLE_CLEAR_OLD_FILES` - Boolean, `True`: Enable deleting files in the `analysis` folder for each analyzer after analysis of an application
* `ENABLE_CUCKOO_EXTRA_INFO` - Boolean, `True`: Enable extracting extra information (list of running processes etc.) besides the usual cuckoo analysis
* `ADB_PATH` - String: Path to the `adb` binary
* `PATH_IFCONFIG` - String: Path to the `ifconfig` binary
* `PATH_DYNAMIC_ANALYSIS` - String: Path to the Dynamic Analysis Folder
