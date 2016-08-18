import base64, binascii, re, subprocess, zipfile
from datetime import datetime

from mhash import *
from mutils import *

# === ZIP EXTRACTION ===
def get_zip_modified(apkpath):
	command = "exiftool {} -p '$ZipModifyDate' -d '%Y-%m-%d'".format(apkpath)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	result = process.communicate()
	if len(result)<1: return None
	return result[0].replace('\n','')

def get_zip_filelist(apkpath):
	zf = zipfile.ZipFile(apkpath)
	files = []
	for f in zf.namelist():
		files.append(f)
	return files



# === APK INFORMATION ===

def verify_apk(apkpath):
	command = 'jarsigner -verify -certs {}'.format(apkpath)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	result = process.communicate()
	if len(result)<1: return None
	result = result[0].splitlines()
	if result[0] == "jar verified.": return True
	return False

def hashes_apk(apkpath):
	data = ''
	with open(apkpath, 'r') as f:
		data = f.read()
	return hash_all(data)



# === CERTIFICATE METHODS ===

def get_certificate_from_apk(apkpath):
	try:
		zf = zipfile.ZipFile(apkpath)
	except Error, e:
		raise e
	certnames = []
	for f in zf.namelist():
		result = re.findall(r'META-INF/.*\.[DR]{1}SA', f)
		if len(result) < 1: continue
		certnames.append(result[0])

	if len(certnames)<1:
		print 'ERROR: Did not find any certificate!'
		return None

	if len(certnames)>1:
		print 'ERROR: Not implemented to store more than one fingerprint for list:',certnames
		return None
	try:
		data = zf.read(certnames[0])
	except KeyError, k:
		print k
		print 'ERROR: Did not find {} in zip file'.format(certnames[0])
		return None
	return data


def get_certificate(data):
	# Get PEM format of *.[DR]SA certificate
	command = 'openssl pkcs7 -inform DER -print_certs'
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = process.communicate(input=data)
	if stderr is not None and stderr != '':
		print "ERROR: subprocess returned error: [{}]".format(stderr.decode())
		return None

	certdata = stdout
	certdata = find_one_result(stdout, r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/\n=]+)-----END CERTIFICATE-----\n")
	if certdata is None:
		print 'ERROR: More than one certificates in the apk!'
		return None
	certdata = base64.b64decode(certdata.replace('\n',''))

	md5 = hash_md5(certdata).upper()
	sha1 = hash_sha1(certdata).upper()
	sha256 = hash_sha256(certdata).upper()

	# Get all information inside the certificate: Serial Number, Subject, Issuer, Validity and Public Key
	command = 'openssl x509 -noout -serial -subject -issuer -dates -pubkey'
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = process.communicate(input=stdout)
	if stderr is not None and stderr != '':
		print "ERROR: subprocess returned error: [{}]".format(stderr.decode())
		return None

	serial = find_one_result(stdout, r'serial=(.*)').upper()
	subject = find_one_result(stdout, r'subject=(.*)').lstrip()
	issuer = find_one_result(stdout, r'issuer=(.*)').lstrip()
	notbefore = find_one_result(stdout, r'notBefore=(.*)')
	notbefore = str(datetime.strptime(notbefore,"%b %d %H:%M:%S %Y %Z"))
	notafter = find_one_result(stdout, r'notAfter=(.*)')
	notafter = str(datetime.strptime(notafter,"%b %d %H:%M:%S %Y %Z"))
	pubkey = find_one_result(stdout, r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/\n=]+-----END PUBLIC KEY-----\n")

	# TODO Actually could be done in previous process using -text
	# Extract public key information
	command = 'openssl rsa -noout -pubin -modulus -text'
	process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = process.communicate(input=pubkey)
	if stderr is not None and stderr != '':
		print "ERROR: subprocess returned error: [{}]".format(stderr.decode())
		return None

	modulus = find_one_result(stdout, r'Modulus=([A-F0-9]+)').upper()
	modulus_len = len(modulus)*4
	exponent = find_one_result(stdout, r'Exponent: ([0-9]+) .*')
	return [md5, sha1, sha256, serial, subject, issuer, notbefore, notafter, modulus, modulus_len, exponent]



# === ANDROIDMANIFEST.XML EXTRACTION ===
# TODO: Check validity of names etc?
def get_manifest(apkpath):
	command = "aapt dump badging {}".format(apkpath)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	output = process.communicate()[0]

	# PACKAGE NAME, VERSIONCODE, VERSIONNAME
	package_name = find_one_result(output, r"package:(?:.*) name='([^']+)'")
	versionCode = find_one_result(output, r"package:(?:.*) versionCode='([^']+)'")
	versionName = find_one_result(output, r"package:(?:.*) versionName='([^']+)'")
	min_sdk = find_one_result(output, r"sdkVersion:'([0-9]+)'")
	if min_sdk is None:
		min_sdk = find_one_result(output, r"targetSdkVersion:'([0-9]+)'")
	max_sdk = find_one_result(output, r"maxSdkVersion:'([0-9]+)'")

	# uses-feature, uses-feature-not-required, uses-implied-feature
	features_normal  = find_result(output, r"uses-feature:(?:.*) name='([^']+)'")
	features_implied = find_result(output, r"uses-implied-feature:(?:.*) name='([^']+)'")
	features_unused  = find_result(output, r"uses-feature-not-required:(?:.*) name='([^']+)'")

	features = [features_normal, features_implied, features_unused]

	# PERMISSIONS
	command = "aapt dump permissions {}".format(apkpath)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	output = process.communicate()[0]

	permissions = []
	for line in output.splitlines():
		columns = line.split(': ')
		if columns[0] == 'package': continue
		# optional-permission: name='android.permission.CALL_PHONE'
		# uses-permission: name='android.permission.INTERNET'
		if columns[0] == 'optional-permission' or columns[0] == 'uses-permission':
			permissions.append(find_one_result(columns[1],r"name='([^']+)'"))
		# permission: com.software.application.permission.C2D_MESSAGE
		elif columns[0] == 'permission':
			permissions.append(columns[1])
		else:
			print 'ERROR: Parsing permissions failed somehow! Data:',permissions
			return None
	permissions = set(permissions)

	# COMPONENTS (
	command = "aapt dump xmltree {} AndroidManifest.xml".format(apkpath)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	output = process.communicate()[0]

	activities = []
	idxa = []
	services = []
	idxs = []
	receivers = []
	idxr = []
	providers = []
	idxp = []
	# http://developer.android.com/guide/topics/manifest/manifest-intro.html
	output = output.splitlines()
	for idx, line in enumerate(output):
		if 'E: activity' in line:
			line = 'A'+line[1:]
			idxa.append(idx)
		elif 'E: service' in line:
			line = 'S'+line[1:]
			idxs.append(idx)
		elif 'E: receiver' in line:
			line = 'R'+line[1:]
			idxr.append(idx)
		elif 'E: provider' in line:
			line = 'P'+line[1:]
			idxp.append(idx)

	activities = search_xmltree(output, idxa, activities)
	services = search_xmltree(output, idxs, services)
	receivers = search_xmltree(output, idxr, receivers)
	providers = search_xmltree(output, idxp, providers)
	return [package_name, versionCode, versionName, permissions, activities, services, receivers, providers, features, min_sdk, max_sdk]

def get_apk_files_hashes(apkpath):
	try:
		zf = zipfile.ZipFile(apkpath)
	except Exception, e:
		raise e

	manifest = 'META-INF/MANIFEST.MF'
	filelist = get_zip_filelist(apkpath)
	if manifest not in filelist: return None

	hashes = []
	if verify_apk(apkpath):
		checked = []
		data = zf.read(manifest)
		results = find_result(data, r'Name: (.*)[\r]?\nSHA1-Digest: (.*)[\r]?\n')
		if results is not None:
			for r in results:
				(a,b) = r
				if a[len(a)-1]=='\r': a=a[:len(a)-1]
				if b[len(b)-1]=='\r': b=b[:len(b)-1]
				r = (a,b)
				file_data = zf.read(r[0])
				md5_file = hash_md5(file_data)
				sha256_file = hash_sha256(file_data)
				ssdeep_file = hash_ssdeep(file_data)
				hashes.append((md5_file, binascii.hexlify(base64.b64decode(r[1])), sha256_file, ssdeep_file, r[0]))
				checked.append(r[0])
		else:
			print 'WARNING: APK [{}] does not contain SHA-1 digests in META-INF/MANIFEST.MF'.format(apkpath)

		# TODO It is also possible that SHA256-Digests exist. e.g. 835ea88e21033f179e6a1e7c8cd1b9ab881c2b3eb9a5e15a98542e7c3706b013.apk

		for f in list(set(filelist)-set(checked)):
			file_data = zf.read(f)
			md5_file = hash_md5(file_data)
			sha1_file = hash_sha1(file_data)
			sha256_file = hash_sha256(file_data)
			ssdeep_file = hash_ssdeep(file_data)
			hashes.append((md5_file, sha1_file, sha256_file, ssdeep_file, f))
		return hashes

	print 'WARNING: JAR Verification of {} failed!'.format(apkpath)
	# Case Verification fails TODO: Only calculate not signed files
	for f in filelist:
		file_data = zf.read(f)
		md5_file = hash_md5(file_data)
		sha1_file = hash_sha1(file_data)
		sha256_file = hash_sha256(file_data)
		ssdeep_file = hash_ssdeep(file_data)
		hashes.append((md5_file, sha1_file, sha256_file, ssdeep_file, f))
		#data = zf.read(f)
		#hashes.append((hash_sha1(data), f))
	return hashes



# === classes.dex Analysis ===
def get_dex(apkpath):
	tmpdex = '/tmp/classes.dex'
	# TODO Check if it doesn't exist
	try:
		zf = zipfile.ZipFile(apkpath)
	except Error, e:
		raise e
	try:
		data = zf.read('classes.dex')
	except KeyError as ke:
		print "An error occurred:", ke.args[0]
		return None

	with open(tmpdex, 'wb') as f:
		f.write(data)

	command = "dexdump {}".format(tmpdex)
	process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
	result = process.communicate()[0]
	
	class_descriptors = find_result(result, r"  Class descriptor  : 'L([^';$]+);'") # $ = no subclasses
	if class_descriptors is None:
		return None
	directories = []
	for c in class_descriptors:
		tmp = c.split('/')
		tmp = "/".join(tmp[:len(tmp)-1])
		if tmp not in directories:
			directories.append(tmp)
	return [directories, class_descriptors]
