import glob
import os
import platform
import re
import subprocess
import sys

import core

OUT_DIR = "./output/"
SYMBOLS_DIR = "."
CODE_AROUND_DIR = OUT_DIR + "code_around/"
SYMBOLS_UNPAK_DIR = OUT_DIR + "unpack_symbols/"
OATDUMP_DIR = OUT_DIR + "oatdump_file/"
REPORT_FILENAME = OUT_DIR + "report.txt"
OATDUMP_TOOL = None
OATFILE_HOST_DIR = ""
OATDUMP_FROM_DEVICE = False
ARCH = None

_CACHED_TOOLCHAIN = None
_CACHED_TOOLCHAIN_ARCH = None

DEFAULT_SCOPE = 16

def SetOatDumpTool(tool):
  global OATDUMP_TOOL
  if os.path.exists(tool):
    OATDUMP_TOOL = tool

def SetOatFileDir(oatDir):
  global OATFILE_HOST_DIR
  if oatDir[-1] != "/":
    oatDir = oatDir + "/"
  if os.path.exists(oatDir):
    OATFILE_HOST_DIR = oatDir

def ToolPath(tool, toolchain=None):
  if not toolchain:
    toolchain = FindToolchain()
  return glob.glob(os.path.join(toolchain, "*-" + tool))[0]

def AnotherArchName():
  archName = ARCH
  if archName == "arm64":
    archName = "aarch64"
  elif archName == "mips64":
    archName = "mips"
  elif archName == "x86_64":
    archName = "x86"
  return archName

def FindToolchain():
  global _CACHED_TOOLCHAIN, _CACHED_TOOLCHAIN_ARCH, ARCH
  if _CACHED_TOOLCHAIN is not None and _CACHED_TOOLCHAIN_ARCH == ARCH:
    return _CACHED_TOOLCHAIN

  # We use slightly different names from GCC, and there's only one toolchain
  # for x86/x86_64. Note that these are the names of the top-level directory
  # rather than the _different_ names used lower down the directory hierarchy!
  gcc_dir = AnotherArchName()

  os_name = platform.system().lower();

  toolchain_path = "%s/toolchains/%s/%s/*-linux-*/bin/" % (os.path.dirname(__file__) , platform.system().lower(), gcc_dir)
  available_toolchains = glob.glob(toolchain_path)

  # get last toolchain
  toolchain = sorted(available_toolchains)[-1]

  _CACHED_TOOLCHAIN = toolchain
  _CACHED_TOOLCHAIN_ARCH = ARCH
  hint = "Using %s toolchain from: %s\n\n" % (_CACHED_TOOLCHAIN_ARCH, _CACHED_TOOLCHAIN)
  core.DebugPrint(hint)
  return _CACHED_TOOLCHAIN


def CallAddr2LineForSet(lib, addr):
  symbols = SYMBOLS_DIR + lib
  if not os.path.exists(symbols):
    symbols = SearchTargetFileInDir(lib, SYMBOLS_DIR)
    if not symbols or IsOatFile(lib):
      return []

  cmd = [ToolPath("addr2line"), "--functions", "--inlines",
      "--demangle", "--exe=" + symbols]
  child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

  child.stdin.write("%s\n" % hex(addr))
  child.stdin.flush()
  records = []
  while True:
    symbol = child.stdout.readline().strip()
    if symbol == "??":
      symbol = None
    location = child.stdout.readline().strip()
    if location == "??:0" or location == "??:?":
      location = None
    if symbol is None and location is None:
      break
    records.append((symbol, location))
    # Write a blank line as a sentinel so we know when to stop
    # reading inlines from the output.
    # The blank line will cause addr2line to emit "??\n??:0\n".
    child.stdin.write("\n")
  child.stdin.close()
  child.stdout.close()
  return records

def StripPC(addr):
  """Strips the Thumb bit a program counter address when appropriate.

  Args:
    addr: the program counter address

  Returns:
    The stripped program counter address.
  """
  global ARCH
  if ARCH == "arm":
    return addr & ~1
  return addr

def IsThumb(addr):
  if ARCH == "arm":
    return addr & 0x1
  else:
    return False

def CallObjdumpForSetWithDataFile(fileName, isThumb):
  cmd = [ToolPath("objdump"),
        "--target=binary",
        "--architecture=" + AnotherArchName(),
        "--disassemble-all",
        fileName]

  if isThumb:
    thumbArg = "--disassembler-options=force-thumb"
    cmd.append(thumbArg)

  dumpStartTag = "<.data>:"
  asm_regexp = re.compile("(^[ a-f0-9]*):([ a-f0-9]*.*)$")
  startAppend = False
  stream = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout
  result = []
  for line in stream:
    if startAppend:
      asmMatch = asm_regexp.match(line)
      if asmMatch:
        if not "is out of bounds" in asmMatch.group(2):
          result.append((asmMatch.group(1), asmMatch.group(2)))
    else:
      if dumpStartTag in line:
        startAppend = True
  stream.close()
  return result

def SearchTargetFileInDir(target, rootDir):
  baseName = os.path.basename(target)
  core.DebugPrint("searching... " + target)
  for root, subFolders, files in os.walk(rootDir):
    for f in files:
      if f == baseName:
        if ("64" in target and "64" in root) or (not "64" in target and not "64" in root):
          fileFound = root + "/" + f
          core.DebugPrint("FOUND" + fileFound)
          return fileFound
  core.DebugPrint("NO FOUND")

def CallObjdumpForSet(lib, start_addr_dec, stop_addr_dec):
  symbols = SYMBOLS_DIR + lib
  if not os.path.exists(symbols):
    symbols = SearchTargetFileInDir(lib, SYMBOLS_DIR)
    if not symbols or IsOatFile(lib):
      return (None, [])

  cmd = [ToolPath("objdump"),
         "--section=.text",
         "--demangle",
         "--disassemble",
         "--start-address=" + start_addr_dec,
         "--stop-address=" + stop_addr_dec,
         symbols]

  stream = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout

  # Function lines look like:
  #   000177b0 <android::IBinder::~IBinder()+0x2c>:
  # We pull out the address and function first. Then we check for an optional
  # offset. This is tricky due to functions that look like "operator+(..)+0x2c"
  funcRegexp = re.compile("(^[a-f0-9]*) \<(.*)\>:$")
  offset_regexp = re.compile("(.*)\+0x([a-f0-9]*)")

  # A disassembly line looks like:
  #   177b2:  b510        push  {r4, lr}
  asm_regexp = re.compile("(^[ a-f0-9]*):([ a-f0-0]*.*)$")

  lines = []
  for line in stream:
    lines.append(line.rstrip())

  stream.close()

  funcSymbol = None
  instList = []
  for line in lines[::-1]:
    asmMatch = asm_regexp.match(line)
    if asmMatch:
      offset = asmMatch.group(1)
      inst = asmMatch.group(2)
      instList.append((offset, inst))
    else:
      if funcRegexp.match(line):
        funcSymbol = line
        break
  if funcSymbol:
    return (funcSymbol, instList[::-1])
  else:
    return (None, [])


def CallObjdumpForSetWithBeforeScope(lib, addr, before_scope = DEFAULT_SCOPE):
  start_addr_dec = hex(StripPC(addr - before_scope))
  stop_addr_dec = hex(StripPC(addr) + 4)
  return CallObjdumpForSet(lib, start_addr_dec, stop_addr_dec)

def IsOatFile(fileName):
  return "classes.dex" in fileName or "boot.oat" in fileName or ".odex" in fileName

def ParseOatdumpStream(oatdumpFileName, stream, addrHexIntToExeSegList):
  linesSaveInFile = []
  firstLine = stream.readline()
  if not "MAGIC:" in firstLine:
    raise Exception("oatdump fail! read first line: >>" +  firstLine + "<<")
  else:
    linesSaveInFile.append(firstLine)

  while True:
    line = stream.readline()
    linesSaveInFile.append(line)
    if "EXECUTABLE OFFSET:" in line:
      break

  offsetLine = stream.readline()
  offsetHexInt = int(offsetLine, 16)

  linesSaveInFile.append(offsetLine)
  addrHexIntList = map(lambda x: x + offsetHexInt, addrHexIntToExeSegList)

  locationPatC = re.compile("^location:\\s*(\\S*)")
  classPatC = re.compile("^\\d*?: (L.*)")
  methodPatC = re.compile("^  \\d*?: (.*)")
  dexPcPatC = re.compile("suspend point dex PC: " + "(0x[0-9a-fA-F]+)")
  linesMethod = []

  location = ""
  clazz = ""
  method = ""
  dexPc = ""
  addrMethodFoundList = []
  lineCount = 0
  linePrintCount = 0
  print "dumping " + oatdumpFileName + " file... "
  for line in stream:
    line = line.rstrip()
    locationMatch = locationPatC.search(line)
    if locationMatch:
      location = locationMatch.group(1)
      linesMethod = []
      if not addrHexIntList:
        break
    else:
      classMatch = classPatC.search(line)
      if classMatch:
        clazz = classMatch.group(1)
        linesMethod = []
        if not addrHexIntList:
          break
      else:
        methodMatch = methodPatC.search(line)
        if methodMatch:
          method = methodMatch.group(1)
          if addrHexIntList:
            linesMethod = []
          else:
            break
        else:
          dexPcMatch = dexPcPatC.search(line)
          if dexPcMatch:
            dexPc = dexPcMatch.group(1)
          else:
            for addr in addrHexIntList:
              offsetPatC = re.compile("^\\s*0x0*" + hex(StripPC(addr))[2:] + ":")
              offsetMatch = offsetPatC.search(line)
              if offsetMatch:
                addrMethodFoundList.append((addr - offsetHexInt, location, clazz, linesMethod))
                print "FIND " + hex(addr) + ", remain " + str(len(addrHexIntList) - 1) + " target"
                addrHexIntList.remove(addr)
                break
    lineCount = lineCount + 1
    modNum = lineCount % 100000
    if not modNum:
      linePrintCount = linePrintCount + 1
    # print str(linePrintCount) + "%  " + line + "\r",
      print "dumping ... " + str(linePrintCount) + " * 100k lines"
    linesSaveInFile.append(line + "\n")
    linesMethod.append(line)

  stream.close()
  if not os.path.exists(oatdumpFileName):
    oatfile = open(oatdumpFileName, 'w')
    oatfile.writelines(linesSaveInFile)
  return (offsetHexInt, addrMethodFoundList)



def CallOatdumpDeviceForFile(fileName, addrHexIntList):
  oatdumpFileName = OATDUMP_DIR + os.path.basename(fileName)
  if os.path.exists(oatdumpFileName):
    stream = open(oatdumpFileName, 'r')
  else:
    cmd = ["adb shell oatdump --oat-file=" + fileName]
    stream = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).stdout
  return ParseOatdumpStream(oatdumpFileName, stream, addrHexIntList)


def CallOatdumpHostForFile(fileName, addrHexIntList):
  oatdumpFileName = OATDUMP_DIR + os.path.basename(fileName)
  if os.path.exists(oatdumpFileName):
    stream = open(oatdumpFileName, 'r')
  else:
    rawOatfileName = OATFILE_HOST_DIR + os.path.basename(fileName)
    oatNoFound = not os.path.exists(rawOatfileName)
    if oatNoFound:
      rawOatfileName = SearchTargetFileInDir(fileName, OATFILE_HOST_DIR)
      if not rawOatfileName:
        rawOatfileName = str(rawOatfileName)
        while oatNoFound:
          oatNoFound = not os.path.exists(rawOatfileName)
          if oatNoFound:
            print rawOatfileName + " do not exist!"
            rawOatfileName = raw_input("Please tell me where is raw oat file of " + fileName + "(INPUT \'N\' IF GIVE UP' ):\n").strip()
            if rawOatfileName == "N":
              return None
          else:
            break
    cmd = [OATDUMP_TOOL + " --oat-file=" + rawOatfileName]
    stream = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).stdout
  return ParseOatdumpStream(oatdumpFileName, stream, addrHexIntList)



def CallOatdumpForFile(fileName, addrList):
  if not IsOatFile(fileName):
    return None
  if OATDUMP_TOOL:
    return CallOatdumpHostForFile(fileName, addrList)
  elif OATDUMP_FROM_DEVICE:
    return CallOatdumpDeviceForFile(fileName, addrList)
  else:
    print "Not set oatdump tool."
    return None

