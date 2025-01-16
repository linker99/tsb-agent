#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys, os
import stat
import getopt
import socket
import ctypes
import json
import hashlib


escape_dirs = ("proc", "lost+found", "sys", "dev")
whitelist_file = './whitelist'
#TPCM_LIB_PATH = './libtssumini.so'
TPCM_LIB_PATH = './libcrypt.so'

TYPE = 'sm3'
DIR = '/'

escape_extension = (".txt", ".png", ".js", ".css", ".sta",
                    ".lni", "dis", ".cad", ".o", ".a", ".log",
                    ".xml", ".lock", ".mo", ".idx",
                    ".local", ".deny", ".LOCK", ".cache",
                    ".h", ".c", ".tar", ".gz", ".html",
                    ".gif", ".old", ".hpp", ".tcc", ".var",
                    ".jpg", ".ini", ".xpt", "tcl", ".am", "omf",
                    ".defs", ".ttf", ".pcf", ".afm", ".pfb", ".gsf",
                    ".pfa", ".xsl", ".kbd", ".svg", ".icon",
                    ".idl", ".swg", ".i", ".vim", ".awk",
                    ".pm", ".pod", ".ipp", ".rdf", ".rws",
                    ".amf", ".cmap", ".alias", ".multi",
                    ".cset", ".desktop", ".dsl", ".elc",
                    ".pbm", ".pdf", ".htm", ".in", ".m4", ".x",
                    ".tcl", ".al", ".omf", ".xpm", ".xinf",
                    ".eps", ".if", ".tmpl", ".glade", ".cfg", ".hhp",
                    ".cpp", ".meta", ".LIB", ".directory", ".lang", ".svn-base",
                    ".XML", ".iso", ".zip", ".json", ".avi", ".swf", ".mp4",
                    "JPG")


class ScanDirExe:
    def __init__(self):
        self.exe_count = 0
        self.file_count = 0
        self.exe_array = []
        self.sm3_handle = None

    def add_node(self, file_path, file_hash, file_size, file_type):
        options = (file_path, file_hash, file_size, file_type, "system")
        self.exe_array.append(options)
        self.exe_count += 1

    def process_dir(self, rootdir):
        global escape_extension
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                sp_name = os.path.splitext(filename)
                if sp_name[1] in escape_extension:
                    continue
                file_path = os.path.join(parent, filename)
                self.process_file(file_path)

    def process_file(self, file_path):
        if os.path.isfile(file_path) is not True:
            return 1

        self.file_count += 1
        if check_isexec(file_path) == 1:
            hash = get_hash(file_path, self.sm3_handle)
            if hash == 0:
                print "get %s hash error" % file_path
                return 1
        else:
            return 1

        file_size = os.path.getsize(file_path)
        self.add_node(file_path, hash, str(file_size), str(4))

    def process_file_force(self, file_path):
        if os.path.isfile(file_path) is not True:
            return 1

        self.file_count += 1

        hash = get_hash(file_path, self.sm3_handle)
        if hash == 0:
            print "get %s hash error" % file_path
            return 1

        file_size = os.path.getsize(file_path)
        self.add_node(file_path, hash, str(file_size), str(4))


def get_hash_sm3(filepath, sm3_handle):
    if sm3_handle == None:
        print 'sm3 handle is None'
        return 0

    try:
        with open(filepath, 'r') as f:
            data = f.read()
            data_len = len(data)

        sbuf_len = ctypes.c_int(data_len)
        sbuf = ctypes.create_string_buffer(data, data_len + 1)    #输入缓存
        rbuf = ctypes.create_string_buffer('', 64 + 1)    #输出缓存
        #sm3_flag = ctypes.c_int(2)    # 1代表硬算法， 2代表软算法

        #ret = sm3_handle.TPCM_SM3(ctypes.byref(sm3_flag), sbuf, sbuf_len, rbuf)
        ret = sm3_handle.py_sm3_hash(sbuf, sbuf_len, rbuf)
        if ret == 0:
            return rbuf.value[:64]

    except Exception as e:
        print e

    return 0


def get_hash_sha1(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        sha1obj = hashlib.sha1()
        sha1obj.update(content)
        return sha1obj.hexdigest()

    except Exception as e:
        print e

    return 0



def get_hash(filepath, sm3_handle):
    if TYPE == 'sha1':
        return get_hash_sha1(filepath)
    else:
        return get_hash_sm3(filepath, sm3_handle)


def check_isexec(file_path):

    if os.access(file_path, os.X_OK) is True:
        return 1

    try:
        fd = open(file_path, 'rb')

        if cmp(fd.read(4), "\177ELF") == 0:
            fd.close()
            return 1

        fd.seek(0)
        if cmp(fd.read(2), "#!") == 0:
            fd.close()
            return 1

        fd.close()

    except Exception as e:
        print e

    return 0


class WhiteListScan():
    def __init__(self):
        self.whitelist_count = 0
        self.file_count = 0
        self.whitelist_array = []

    def Get_root_dir_entry(self, path):
        global escape_dirs

        dirs = os.listdir(path)

        newdirs = []
        for dir_one in dirs:
            if dir_one not in escape_dirs:
                newdirs.append(dir_one)

        newdirs.sort()
        return newdirs

    def commit_to_file(self, whitelist_file):
        try:
            with open(whitelist_file, 'a') as f:
                for i, enum in enumerate(self.whitelist_array):
                    cmdstring = "%s %s\n" % (enum[0].replace(" ", "-"), enum[1])
                    f.writelines(cmdstring)

            print "file count: [%d] whitelist count: [%d]" % (self.file_count, self.whitelist_count)

        except Exception as e:
            print e
            return

        os.chmod(whitelist_file, os.stat(whitelist_file).st_mode|stat.S_IXUSR)

    def scan_dir(self, dirpath):
        sd = ScanDirExe()
        sd.sm3_handle = TPCM_handle
        sd.process_dir(dirpath)
        self.file_count += sd.file_count
        self.whitelist_count += sd.exe_count
        if sd.exe_count != 0:
            self.whitelist_array = self.whitelist_array + sd.exe_array

    def scan_file(self, filepath):
        sd = ScanDirExe()
        sd.sm3_handle = TPCM_handle
        sd.process_file(filepath)
        self.file_count += sd.file_count
        self.whitelist_count += sd.exe_count
        if sd.exe_count != 0:
            self.whitelist_array = self.whitelist_array + sd.exe_array

    def scan_whitelist(self):
        scan_dirs = self.Get_root_dir_entry(DIR)
        for entry_one in scan_dirs:
            Entry = DIR + entry_one
            if os.path.isdir(Entry):
                print "scan %s" % Entry

                self.scan_dir(Entry)
            else:
                self.scan_file(Entry)


if __name__ == '__main__':

    try:
        options, args = getopt.getopt(sys.argv[1:], "t:d:")
    except getopt.GetoptError:
        print "getopt error, please check!"
        sys.exit()

    for name, value in options:
        if name in '-t':
            TYPE = value
        if name in '-d':
            DIR = value

    if os.path.exists(whitelist_file):
        os.remove(whitelist_file)

    try:
        TPCM_handle = ctypes.cdll.LoadLibrary(TPCM_LIB_PATH)   #加载卡驱动库里的接口

    except Exception as e:
        print e
        os._exit(-1)

    try:
        wl = WhiteListScan()

        wl.scan_whitelist()
        wl.commit_to_file(whitelist_file)

    except Exception as e:
        print e
        os._exit(-1)
