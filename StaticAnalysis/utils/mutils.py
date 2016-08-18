import re

# === COMMON UTILS ===

def find_result(data, regex):
	result = re.findall(regex, data)
	if len(result)<1:
		print 'ERROR: No results for regex [{}] '.format(regex)
		return None
	return result

def find_one_result(data, regex):
	result = find_result(data, regex)
	if result is None:
		return None
	if len(result) > 1:
		print 'ERROR: More than 1 results for {}: '.format(regex), result
		return None
	return result[0]

def search_xmltree(xmltreedata, idxe, elements):
	for idx in idxe:
		prependix  = re.search(r'[^ \t]', xmltreedata[idx]).start()
		prependix += 2
		spaces = ' '*prependix
		data = ''
		for lineidx in range(idx+1,len(xmltreedata)):
			if not xmltreedata[lineidx].startswith(spaces):
				break
			if xmltreedata[lineidx][len(spaces)]!=' ':
				data+=xmltreedata[lineidx]
		r = find_one_result(data, r'android:name[^=]+="([^"]+)"')
		if r is not None:
			elements.append(r)
		else:
			# TODO: Use A: :(0x01010003)=".PromptActivity" (Raw: ".PromptActivity") Regex
			return None
	return elements

def print_array(array, title):
	print "=== " + title + " ===\n"
	for e in array: print e
	print

def print_dict(mdict, title=None):
	if title is not None: print "=== " + title + " ===\n"
	for k in mdict.keys():
		print k,
		if type(mdict[k]) is list:
			for v in mdict[k]: print v
		else:
			print mdict[k]
	if title is not None: print

def print_split_string(title, string, splitchar='|', width=78):
	print title.ljust(width)
	print '-'*width
	string = string.split(splitchar)
	for i in string: print i
	print

def print_list(title, mylist, width=78):
	print title.ljust(width)
	print '-'*width
	for i in mylist: print i[0] # sqlite fetchall results are tuples with an extra null element
	print
