import optparse
import rarfile
import zipfile
from threading import Thread

def extract_zip(zfile, password):
	try:
		zfile.extractall(pwd=password)
		print "[+] Password Found: " + password + '\n'
	except:
		pass

def main():
	parser = optparse.OptionParser("usage %prog "+\
			"-f <zipfile> -d <dictionary>")
	parser.add_option('-f', dest='zname', type='string',\
				help='specify zip file')
	parser.add_option('-d', dest='dname', type='string',\
				help='specify dictionary file')
	(options, arg) = parser.parse_args()
	if (options.zname == None) | (options.dname == None):
		print parser.usage
		exit(0)
	else:
		zname = options.zname
		dname = options.dname

	ext = zname.rsplit(".",1)[1].lower()
	if ext == "zip":
		zFile = zipfile.ZipFile(zname)
	elif ext == "rar":
		zFile = rarfile.RarFile(zname)
	else:
		raise StandardError("Unknown format %s" % ext)
	passFile = open(dname)

	d = [ x.strip('\n') for x in passFile.readlines() ]
	dlen = len(d)
	test = list()

	def add( d, m ):
		psw = ""
		for i in m:
			psw += d[i]
		return psw

  # TODO: Need to make this a recursive function
	for i in range(dlen):
		test.append( add(d,[i]) )
		for j in range(dlen):
			if j == i: continue
			test.append( add(d,[i,j]) )
			for k in range(dlen):
				if k == i or k == j: continue
				test.append( add(d,[i,j,k]) )
				for l in range(dlen):
					if (l == i) or (l == j or l == k): continue
					test.append( add(d,[i,j,k,l]) )
					for m in range(dlen):
						if (m == i) or (m == j or ( m == k or m == l)): continue
						test.append( add(d,[i,j,k,l,m]) )

	for password in test:
		t = Thread(target=extract_zip, args=(zFile, password))
		t.start()
	print "tested %d combinations" % len(test)

if __name__ == '__main__':
	main()