import hashlib
import sys
import subprocess
from PyQt4.QtCore import *
from PyQt4.QtGui import *
__version__ = "1.0.0"

BLOCKSIZE = 65536

class ZhakraPro(QTabWidget):
    def __init__(self, parent=None):
        super(ZhakraPro, self).__init__(parent)
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        self.addTab(self.tab1, "File Integrity")
        self.addTab(self.tab2, "View Internet Connections")
        self.addTab(self.tab3, "Help")

        self.tab1UI()
        self.tab2UI()
        self.tab3UI()

        
    def tab1UI(self):
        self.lineedit_fname = QLineEdit("Enter File name or file path")

        self.combobox_options = QComboBox()
        self.combobox_options.addItems(["Select Hash Function", "SHA1", "SHA256", "SHA384", "SHA512", "MD5"])

        self.btn_fhash = QPushButton("Hash File")
        self.browser = QTextBrowser()
        self.browser.setAlignment(Qt.AlignCenter)
        
        vbox1 = QVBoxLayout()
        vbox1.addWidget(self.lineedit_fname)
        vbox1.addWidget(self.combobox_options)
        
        vbox1.addWidget(self.browser)
        self.tab1.setLayout(vbox1)
        self.setGeometry(10, 10, 1000, 500)
        
        self.connect(self.combobox_options,
                     SIGNAL("currentIndexChanged(int)"), self.updateUi)
        self.setWindowTitle("ZhakraPro File Integrity Validator and Internet Monitor")

    def tab2UI(self):
        vbox2 = QVBoxLayout()
        hbox = QHBoxLayout()
        
        self.btn_acon = QPushButton("View Established Connections")
        self.btn_acon.clicked.connect(self.viewCon)
        
        self.btn_rprocess = QPushButton("View Running Processes")
        self.btn_rprocess.clicked.connect(self.viewProc)

        self.btn_dsk = QPushButton("View Statistics")
        self.btn_dsk.clicked.connect(self.nt_usage)

        self.btn_iptable = QPushButton("View Process Users")
        self.btn_iptable.clicked.connect(self.pusers)
        
        self.browser1 = QTextBrowser()
        self.browser1.setAlignment(Qt.AlignCenter)

        hbox.addWidget(self.btn_acon)
        hbox.addWidget(self.btn_rprocess)
        hbox.addWidget(self.btn_dsk)
        hbox.addWidget(self.btn_iptable)
        vbox2.addLayout(hbox)

        vbox2.addWidget(self.browser1)
        self.tab2.setLayout(vbox2)
        

            
    def tab3UI(self):
        self.browser2 = QTextBrowser()
        self.browser2.setText("This application is written in Python 2.7.14 and PyQt4."+"\n"\
                             +"Version 1.0.0" + "\n"\
                             +"author: Daniel Osinachi N." +"\n"\
                              +"dan.ossy.do@gmail.com"+"\n"\
                              +"Copyright (C) 2018 Daniel Osinachi N.")
            
        vbox3 = QVBoxLayout()
        vbox3.addWidget(self.browser2)
        self.tab3.setLayout(vbox3)

    

    def updateUi(self):
        ind = int(self.combobox_options.currentIndex())

        if ind == 1:
            self.Zhak_sha1()
        elif ind == 2:
            self.Zhak_sha256()
        elif ind == 3:
            self.Zhak_sha384()
        elif ind == 4:
            self.Zhak_sha512()
        elif ind == 5:
            self.Zhak_md5()
            
            

    def Zhak_sha1(self):
        fname = str(self.lineedit_fname.text())
        
        hasher = hashlib.sha1()
        try:
            with open(fname, 'rb') as afile_tohash:
                buf = afile_tohash.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile_tohash.read(BLOCKSIZE)
                    chksum1 = hasher.hexdigest()
                    self.browser.setText("The SHA1 Checksum for " + " %s " % fname + " : " + " %s "  % chksum1)
        except Exception, IOError:
            self.browser.setText("No such file in your current directory, specify file path.")

    def Zhak_sha256(self):
        
        fname = str(self.lineedit_fname.text())
        
        hasher = hashlib.sha256()
        try:
            with open(fname, 'rb') as afile_tohash:
                buf = afile_tohash.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile_tohash.read(BLOCKSIZE)
                    chksum2 = hasher.hexdigest()
                    self.browser.setText("The SHA256 Checksum for " + " %s " % fname + " : " + " %s "  % chksum2)
        except Exception, IOError:
            self.browser.setText("No such file in your current directory, specify file path.")

    def Zhak_sha384(self):
        fname = str(self.lineedit_fname.text())
        
        hasher = hashlib.sha384()
        try:
            with open(fname, 'rb') as afile_tohash:
                buf = afile_tohash.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile_tohash.read(BLOCKSIZE)
                    chksum3 = hasher.hexdigest()
                    self.browser.setText("The SHA384 Checksum for " + " %s " % fname + " : " + " %s "  % chksum3)
        except Exception, IOError:
            self.browser.setText("No such file in your current directory, specify file path.")

    def Zhak_sha512(self):
        fname = str(self.lineedit_fname.text())
        
        hasher = hashlib.sha512()
        try:
            with open(fname, 'rb') as afile_tohash:
                buf = afile_tohash.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile_tohash.read(BLOCKSIZE)
                    chksum5 = hasher.hexdigest()
                    self.browser.setText("The SHA512 Checksum for " + " %s " % fname + " : " + " %s "  % chksum5)
        except Exception, IOError:
            self.browser.setText("No such file in your current directory, specify file path.")

    def Zhak_md5(self):
        fname = str(self.lineedit_fname.text())
        
        hasher = hashlib.md5()
        try:
            with open(fname, 'rb') as afile_tohash:
                buf = afile_tohash.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile_tohash.read(BLOCKSIZE)
                    chksumM5 = hasher.hexdigest()
                    self.browser.setText("The MD5 for " + " %s " % fname + " : " + " %s "  % chksumM5)
        except Exception, IOError:
            self.browser.setText("No such file in your current directory, specify file path.")



    def viewCon(self):
        activeCon = subprocess.check_output(['netstat', '-atulpn'])
        self.browser1.setText(activeCon)

    def viewProc(self):
        activePro = subprocess.check_output(['netstat', '-alpn'])
        self.browser1.setText(activePro)

    def nt_usage(self):
        nt_stat = subprocess.check_output(['netstat', '-s'])
        self.browser1.setText(nt_stat)

    def pusers(self):
        proc_user = subprocess.check_output(['netstat', '-e'])
        self.browser1.setText(proc_user)
            

app = QApplication(sys.argv)
form = ZhakraPro()
form.show()
app.exec_()
                
        
                     
        
