#!/usr/bin/python

# Name: python.py
# Author: Joseph Teale
# Created: 28/09/2017
# ModDate: 28/09/2017
# Purpose: Unknown

import hashlib, sys, os, fnmatch, zipfile, fileinput, PyPDF2, getopt, time, getpass


ALGS = ["md5","sha1"]
PASS_FILE="pass.txt"
REPORT = "report.html"

# read file and store passwords
def read_passwords(passfile):
    passwords = []
    for line in fileinput.input([passfile]):
        passwords.append(line.strip())
    return passwords

    
#hashes files recusrively as per provided path   
def file_hash(path, entries):
    f = open('hashes.txt' , 'w')
    header = time.strftime("%H:%M:%S") + " "+"username:"+" " + getpass.getuser() +"\n"
    f.write(header)
    for alg in ALGS:
        f.write(alg+" " + "Start" +"\n")
        print alg
        f_count=0
        for folder, subfolders, files in os.walk(path):
            for file in files:
                files = os.path.join(os.path.abspath(folder), file)
                if alg == "md5":
                    hasher = hashlib.md5()
                else:
                    hasher = hashlib.sha1()
                    
                f_count+=1
                with open(files, 'rb') as file_to_hash:
                    buf = file_to_hash.read()
                    hasher.update(buf)
                    message = hasher.hexdigest() + "\t" + files + "\n" 
                    f.write(message)
    f.flush()
    f.close
#attempts to unzip encrypted zip files            
def dictionary_unzip(zip_file, passwords, entries, path):
    for word in passwords:
        print "trying to extract with password '%s'" % word
        try:
            zip_file.extractall(pwd=word)
        except Exception, e:
            print "FAIL: %s" % e[0]
            continue
        print "SUCCEED" 
        message =("password to"+" " + path + " is " + word)
	report_item(entries, message)

#attempts to unzip files, passes if encrypted            
def unzip(path, passwords, entries):
    zfile = zipfile.ZipFile(path)
    print "Extracting %s" % path
    zfile.printdir()
    try:
        zfile.extractall()
    except RuntimeError, e:
            if e.message.find("password required") > 0:
                print "Attempting dictionary attack"
                dictionary_unzip(zfile, passwords, entries, path)

# handles path names for unzipping functions
def unzip_all_the_things(path, entries, passwords):
    for folder, subfolders, files in os.walk(path):
        for subfolder in subfolders:
            new_path = os.path.join(folder, subfolder)
            unzip_all_the_things(new_path, entries, passwords)
        for f in files:
            f_path = os.path.join(folder, f)
            if zipfile.is_zipfile(f_path):
                unzip(f_path, passwords, entries)

#attempts to decrypt encrypted pdfs
def crack_pdf(path, entries, passwords):
    f = PyPDF2.PdfFileReader(file(path, "rb"))
    print f
    for word in passwords: 
            print "trying to decrypt using %s" %word
            key = f.decrypt(word)
            if key == 0:
                print "failed using %s" %word
            else:
                 message = ("password to %s is %s" % (path, word))
                 report_item(entries, message)
                 break
          
#checks if pdf is encrypted       
def check_encrypt(path, entries, passwords):
        f = PyPDF2.PdfFileReader(file(path, "rb"))
        if f.isEncrypted:
            crack_pdf(path, entries, passwords)

# bases pdf on file extention, passes to check_encrypt 
def pdf_find(path, entries, passwords):
        for folder, subfolders, files in os.walk(path):
                for fFile in files:
                    if fFile.endswith(".pdf"):
                        new_path = os.path.join(os.path.abspath(folder), fFile)
                        check_encrypt(new_path, entries, passwords)


def report_header(start_time, end_time, user):
    return """<html>
<head>
  <link rel="stylesheet"
        href="styles.css">
</head>
<body>
  <table>
    <tr>
      <th>start time:</th><td>%s</td>
      <th>end time:</th><td>%s</td>
      <td>username:</th><td>%s</td>
    </tr>
  </table>
"""  % (start_time, end_time, user)


def report_footer():
    return """</body>
</html>
"""

def report_item(entries, message):
    entries.append("  <p>%s</p>\n" % message)

    
def write_report(start_time, end_time, user, entries):
    report_file = open(REPORT, 'w')
    report_file.write(report_header(start_time, end_time, user))
    for entry in entries:
        report_file.write(entry)
    report_file.write(report_footer())
    report_file.flush()
    report_file.close()
                      

def usage():
    print """You must pass at least one of these flags:

 -a / --all : do everything
 -d / --decrypt: decrypt files
 -h / --hash: print hash report
 -u / --unzip: unzip files below path

Optionally you may provide a path as the penultimate argument
final argument will be pass file (defaults to pass.txt).
"""
 

def main():
    start_time = time.strftime("%H:%M:%S")
    entries = []

    options, remainder = getopt.getopt(
        sys.argv[1:], 'audh', ['all','unzip', 'decrypt', 'hash',])

    if len(remainder) == 0:
        path = os.getcwd()
        passfile = PASS_FILE
    else:
        path = remainder[0]
        passfile = remainder[1]	
    passwords = read_passwords(passfile)


    did_something = False 
    for opt, arg in options:
        if opt in ('-u', '--unzip'):
            did_something = True
            unzip_all_the_things(path, entries, passwords)
        if opt in ('-a', '--all'):
            did_something = True
            unzip_all_the_things(path, entries, passwords)
            pdf_find(path, entries, passwords)
            file_hash(path, entries)
        if opt in ('-d', '--decrypt'):
            did_something = True            
            pdf_find(path, entries, passwords)
            unzip_all_the_things(path, entries, passwords)
        if opt in ('-h', '--hash'):
            did_something = True            
            file_hash(path, entries)

    if did_something == False:
        usage()
    else:
        end_time = time.strftime("%H:%M:%S")
        write_report(start_time, end_time, getpass.getuser(), entries)


if __name__ == "__main__":
    main()
