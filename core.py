import glob
import os
import re
import tempfile

import tool

INIT_NUM = -1
INIT_STR = ""
DEBUGGING = False

DEVIDED_LINE = "-" * 70
DEVIDED_LINE_LAYER = "=" * 80
DEVIDED_LINE_FRAME = "*" * 80

REPORT = None
DETAIL = False
SHELL_PRINT = False
BTX_NEED_SC = True
BTX_NEED_ASM = True

def ProcessTombStone(lines):
  global REPORT
  MkdirSafely(tool.OUT_DIR)
  REPORT = open(tool.REPORT_FILENAME, "w")
  tombcore = TombCore(lines)
  tombcore.parseOatAddrs()
  tombcore.generateReport()
  print "Success! You can get report file: " + REPORT.name
  REPORT.close()

def WidthForArch():
  if tool.ARCH == "arm64" or tool.ARCH == "mips64" or tool.ARCH == "x86_64":
    width = "16"
  else:
    width = "8"
  return width

def ProcessBackTrace(lines):
  btFramePatC = re.compile(
      ".*"                                                 # Random start stuff.
      "\#(?P<frame>[0-9]+)"                                # Frame number.
      "[ \t]+pc[ \t]+"                                     # (space)pc(space).
      "(?P<offset>[0-9a-f]{" + WidthForArch() + "})[ \t]+"       # Offset (hex number given without
                                                           #         0x prefix).
      "(?P<lib>\[[^\]]+\]|[^\r\n \t]*)"                    # Library name.
      "( \(offset (?P<segOffset>0x[0-9a-fA-F]+)\))?"       # Offset into the file to find the start of the shared so.
      "(?P<symbolpresent> \((?P<symbol>.*)\))?")           # Is the symbol there?
  btFrameList = []
  for line in lines:
    lineMatch = btFramePatC.search(line)
    if lineMatch:
      frame = lineMatch.group("frame")
      offset = lineMatch.group("offset")
      lib = lineMatch.group("lib")
      addr = offset
      addrHexInt = int(addr, 16)
      addrKey = (lib, addrHexInt)
      btFrameList.append((frame, addrKey))
  print " BACKTRACE:\n\n"
  for btFrame in btFrameList:
    PrintThreadBt(btFrame)

def ProcessHexCode(lines, isThumb):
  temp = open(tool.CODE_AROUND_DIR + "tempData", "wb")
  temp.write(bytearray(BytesFromLines(lines)[1]))
  temp.close()
  instList = tool.CallObjdumpForSetWithDataFile(temp.name, isThumb)
  os.remove(temp.name)
  print "ASM CODE:"
  for (offset, inst) in instList:
    print offset + ":" + inst

def BytesFromLines(lines):
  bytes = []
  wordPatC = re.compile("[ \t]*([a-f0-9]{" + WidthForArch() + "})")
  startAddr = None
  for line in lines:
    wordList = wordPatC.findall(line)
    if wordList and len(wordList) > 1:
      if not startAddr:
        startAddr = wordList[0]
      wordBytes = BytesLE(wordList[1:])
      bytes.extend(wordBytes)
  return (startAddr, bytes)

def BytesLE(wordList):
  bytes = []
  for word in wordList:
    tmpReversedList = []
    while word:     
      tmpReversedList.append(word[0:2])  
      word = word[2:]
    for hexStr in reversed(tmpReversedList):
      bytes.append(int(hexStr, 16))
  return bytes

def UnpackSymbolsTgz(symbolsTgz):
  if symbolsTgz:
    symbolsUnpakDir = tool.SYMBOLS_UNPAK_DIR
    if not os.path.exists(symbolsUnpakDir + "out/target/product"):
      print "unpacking... " + symbolsTgz
      os.system("mkdir -p " + symbolsUnpakDir + "&& tar xzf " + symbolsTgz + " -C " + symbolsUnpakDir + " > /dev/null")
    tool.SYMBOLS_DIR = glob.glob(symbolsUnpakDir + "out/target/product/*/symbols/")[0]

def PrintlnToReport(strline):
  if REPORT:
    REPORT.write(strline + "\n")
  elif SHELL_PRINT:
    print strline

def MkdirSafely(dirName):
  if not os.path.exists(dirName):
    os.mkdir(dirName)

def MatchLineByPat(line, patStr):
  return re.compile(patStr).search(line)

def BlockFromCodeAroundOrMemNear(threadInfo, regName):
  if regName in threadInfo.blocks.memoryNearBlockDict:
    return threadInfo.blocks.memoryNearBlockDict[regName]
  elif regName in threadInfo.blocks.codeAroundBlockDict:
    return threadInfo.blocks.codeAroundBlockDict[regName]

def DebugPrint(msg):
  if DEBUGGING:
    print msg

def DumpThreadBlocks(threadBlocks):
  DebugPrint("headBlock start: " + str(threadBlocks.headBlock.startIndex))
  DebugPrint("headBlock end: " + str(threadBlocks.headBlock.endIndex))

  DebugPrint("backtraceBlock start: " + str(threadBlocks.backtraceBlock.startIndex))
  DebugPrint("backtraceBlock end: " + str(threadBlocks.backtraceBlock.endIndex))

  DebugPrint("stackBlock start: " + str(threadBlocks.stackBlock.startIndex))
  DebugPrint("stackBlock end: " + str(threadBlocks.stackBlock.endIndex))

  for (k,v) in threadBlocks.memoryNearBlockDict.items(): 
    msg = "memoryNearBlockDict[%s]=" % k,v
    DebugPrint(msg)
    DebugPrint(str(v.startIndex) + "~" + str(v.endIndex))

  for (k,v) in threadBlocks.codeAroundBlockDict.items(): 
    msg = "codeAroundBlockDict[%s]=" % k,v
    DebugPrint(msg)
    DebugPrint(str(v.startIndex) + "~" + str(v.endIndex))


def DumpThreadBlocksList(threadBlocksList, logBlockList, mapBlock):
    for threadBlocks in threadBlocksList:
      DebugPrint("\n\nthread block:")
      DumpThreadBlocks(threadBlocks)

    for logBlock in logBlockList:
      DebugPrint("\n\nlog blocks:")
      DebugPrint(str(logBlock.startIndex) + "~~" + str(logBlock.endIndex))

    if mapBlock:
      DebugPrint("\n\nmap: " + str(mapBlock.startIndex) + "~~" + str(mapBlock.endIndex))

def PrintThreadBt(btFrame):
  arrow = "v------>"
  if tool.ARCH == "arm64" or tool.ARCH == "mips64" or tool.ARCH == "x86_64":
    arrow = "v-------------->"
  (frame, addrKey) = btFrame
  (lib, addrHexInt) = addrKey
  addr = hex(addrHexInt)
  print "<#" + frame + ">" 
  print DEVIDED_LINE_LAYER
  (addr2lineLayers, (funcSymbol, instList)) = (tool.CallAddr2LineForSet(lib, addrHexInt), tool.CallObjdumpForSetWithBeforeScope(lib, addrHexInt))
  if addr2lineLayers:
    layerCount = len(addr2lineLayers) - 1
    for (symbol, source) in addr2lineLayers:
      if layerCount > 0:
        layerCount = layerCount - 1
        vaddr = arrow
      else:
        vaddr = addr
      print " " + vaddr + " " + symbol + "  at  " + lib
      print DEVIDED_LINE
      print " source line: " + source
      print DEVIDED_LINE_LAYER
  else:
    print " " + addr + " " + lib
  if funcSymbol:
    print " asm code around " + funcSymbol
    for (offset, inst) in instList:
      if hex(tool.StripPC(int(addr, 16)))[2:] == offset.strip():
        prefix = "==>"
      else:
        prefix = "   "
      print prefix + offset + ":" + inst
  print DEVIDED_LINE_LAYER
  print "\n"

class Block:
  def __init__(self):
    self.startIndex = INIT_NUM
    self.endIndex = INIT_NUM

class ThreadBlocks:
  def __init__(self):
    self.headBlock = Block()
    self.backtraceBlock = Block()
    self.stackBlock = Block()
    self.memoryNearBlockDict = dict()
    self.codeAroundBlockDict = dict()

class ThreadInfo:
  def __init__(self):
    self.pid = INIT_STR
    self.tid = INIT_STR
    self.pname = INIT_STR
    self.tname = INIT_STR
    self.regDict = dict()
    self.codeAroundFileDict = dict()
    self.btFrameList = []
    blocks = None

class MapItem:
  def __init__(self):
    self.startAddr = INIT_NUM
    self.endAddr = INIT_NUM
    self.file = INIT_STR
    self.accessMod = 0

class LocationItem:
  def __init__(self):
    self.startAddr = INIT_NUM
    self.endAddr = INIT_NUM
    self.location = INIT_STR

class TombCore:
  lines = INIT_STR

  arch = INIT_STR

  fingerprintPatC = re.compile(
        "^Build fingerprint: "
        "\'(?P<brand>.*?)/"
        "(?P<product>.*?)/"
        "(?P<device>.*?):(?P<andVersion>.*?)/"
        "(?P<buildId>.*?)/"
        "(?P<buildNumber>.*?):(?P<variant>.*?)/"
        "(?P<key>.*?)\'$")
  abiPatC = re.compile("^ABI: \'(.*)\'")
  registerNames = {
      "arm": "r0|r1|r2|r3|r4|r5|r6|r7|r8|r9|sl|fp|ip|sp|lr|pc|cpsr",
      "arm64": "x0|x1|x2|x3|x4|x5|x6|x7|x8|x9|x10|x11|x12|x13|x14|x15|x16|x17|x18|x19|x20|x21|x22|x23|x24|x25|x26|x27|x28|x29|x30|sp|pc|pstate",
      "mips": "zr|at|v0|v1|a0|a1|a2|a3|t0|t1|t2|t3|t4|t5|t6|t7|s0|s1|s2|s3|s4|s5|s6|s7|t8|t9|k0|k1|gp|sp|s8|ra|hi|lo|bva|epc",
      "mips64": "zr|at|v0|v1|a0|a1|a2|a3|a4|a5|a6|a7|t0|t1|t2|t3|s0|s1|s2|s3|s4|s5|s6|s7|t8|t9|k0|k1|gp|sp|s8|ra|hi|lo|bva|epc",
      "x86": "eax|ebx|ecx|edx|esi|edi|x?cs|x?ds|x?es|x?fs|x?ss|eip|ebp|esp|flags",
      "x86_64": "rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15|cs|ss|rip|rbp|rsp|eflags",
  }

  def updateAbiRegexes(self):
    if self.arch == "arm64" or self.arch == "mips64" or self.arch == "x86_64":
      self.width = "{16}"
      self.spacing = "        "
    else:
      self.width = "{8}"
      self.spacing = ""

  def setAbi(self, lines):
    for line in lines:
      abiMatch = self.abiPatC.search(line)
      if abiMatch:
        self.arch = abiMatch.group(1)
        tool.ARCH = self.arch
        break
    if not self.arch:
      self.arch = "arm"
      tool.ARCH = "arm"
    DebugPrint("arch is " + self.arch)

  def endPrevBlock(self, block, index):
    if block:
      block.endIndex = index - 1

  def linesOfBlock(self, block):
    if block:
      return self.lines[block.startIndex:block.endIndex + 1]
    else:
      return []

  def preProcess(self):
    self.setAbi(self.lines)
    self.updateAbiRegexes()
    for line in self.lines:
      fingerprintMatch = self.fingerprintPatC.search(line)
      if fingerprintMatch:
        DebugPrint("finger match")
        self.brand = fingerprintMatch.group("brand")
        self.product = fingerprintMatch.group("product")
        self.device = fingerprintMatch.group("device")
        self.andVersion = fingerprintMatch.group("andVersion")
        self.buildId = fingerprintMatch.group("buildId")
        self.buildNumber = fingerprintMatch.group("buildNumber")
        self.variant = fingerprintMatch.group("variant")
        self.key = fingerprintMatch.group("key")
        break

  def dump(self):
    DebugPrint("dumping ...")
    DebugPrint(self.arch)
    DebugPrint(self.brand)
    DebugPrint(self.product)
    DebugPrint(self.device)
    DebugPrint(self.andVersion)
    DebugPrint(self.buildId)
    DebugPrint(self.buildNumber)
    DebugPrint(self.variant)
    DebugPrint(self.key)

  def fetchAddrInfo(self, addrKey):
    (lib, addr) = addrKey
    if SHELL_PRINT or not addrKey in self.addrInfoDict:
      if tool.IsOatFile(lib):
        if not addrKey in self.addrInfoDict:
          return None
      else:
        self.addrInfoDict[addrKey] = (tool.CallAddr2LineForSet(lib, addr), tool.CallObjdumpForSetWithBeforeScope(lib, addr))
    return self.addrInfoDict[addrKey]

  def parseOatAddrs(self):
    # must after parse backtrace
    MkdirSafely(tool.OATDUMP_DIR)
    for (fileName, addrList) in self.oatAddrLibDict.items():
      oatDumpResult = tool.CallOatdumpForFile(fileName, addrList)
      if oatDumpResult:
        (exeOffsetHexInt, addrMethodFoundList) = oatDumpResult
        self.oatFileOffsetDict[fileName] = exeOffsetHexInt
        for (addr, location, clazz, linesMethod) in addrMethodFoundList:
          self.addrInfoDict[(fileName, addr)] = (location, clazz, linesMethod)

  def parseBackTrace(self, threadInfo):
    btBlock = threadInfo.blocks.backtraceBlock
    # Examples of matched trace lines include lines from tombstone files like:
    #   #00  pc 001cf42e  /data/data/com.my.project/lib/libmyproject.so
    #
    # Or lines from AndroidFeedback crash report system logs like:
    #   03-25 00:51:05.520 I/DEBUG ( 65): #00 pc 001cf42e /data/data/com.my.project/lib/libmyproject.so
    # Please note the spacing differences.
    btFramePatC = re.compile(
        ".*"                                                 # Random start stuff.
        "\#(?P<frame>[0-9]+)"                                # Frame number.
        "[ \t]+pc[ \t]+"                                     # (space)pc(space).
        "(?P<offset>[0-9a-f]" + self.width + ")[ \t]+"       # Offset (hex number given without
                                                             #         0x prefix).
        "(?P<lib>\[[^\]]+\]|[^\r\n \t]*)"                    # Library name.
        "( \(offset (?P<segOffset>0x[0-9a-fA-F]+)\))?"       # Offset into the file to find the start of the shared so.
        "(?P<symbolpresent> \((?P<symbol>.*)\))?")           # Is the symbol there?

    threadShouldCollectOat = DETAIL or threadInfo == self.threadInfoList[0]
    for line in self.linesOfBlock(btBlock):
      lineMatch = btFramePatC.search(line)
      if lineMatch:
        frame = lineMatch.group("frame")
        offset = lineMatch.group("offset")
        lib = lineMatch.group("lib")
        segOffset = lineMatch.group("segOffset")
        symbol = lineMatch.group("symbol")
        offsetHexInt = int(offset, 16)
        mapItem = self.findAddrInMaps(offsetHexInt)
        if mapItem and mapItem.file == lib and mapItem.accessMod == 4:
          baseAddr = 0
          if tool.IsOatFile(lib):
            baseAddr = mapItem.startAddr
          else:
            baseAddr = self.findAddrInMaps(mapItem.startAddr - 1).startAddr
          addr = hex(offsetHexInt - baseAddr)
        else:
          if segOffset:
            addr = hex(int(segOffset, 16) + offsetHexInt)
            if tool.IsOatFile(lib):
              for mapItem in self.mapItemList:
                mapItemX = self.findAddrInMaps(mapItem.endAddr + 1)
                if mapItem.file == lib and mapItem.accessMod == 4 and mapItemX.accessMod == 5:
                  lenOfItemR = mapItem.endAddr - mapItem.startAddr + 1
                  lenOfItemX = mapItemX.endAddr - mapItemX.startAddr + 1
                  addr = hex(int(addr, 16) - lenOfItemR)
                  if int(addr, 16) > lenOfItemX:
                    addr = hex(int(addr, 16) - lenOfItemR)
                  break
          else:
            addr = offset

        addrHexInt = int(addr, 16)
        addrKey = (lib, addrHexInt)
        if tool.IsOatFile(lib) and threadShouldCollectOat:
          if lib in self.oatAddrLibDict:
            if not addrHexInt in self.oatAddrLibDict[lib]:
              self.oatAddrLibDict[lib].append(addrHexInt)
          else:
            self.oatAddrLibDict[lib] = [addrHexInt]
        threadInfo.btFrameList.append((frame, addrKey))

  def findAddrInMaps(self, addr):
    if not self.mapItemList or addr < self.mapItemList[0].startAddr or addr > self.mapItemList[-1].endAddr:
      return None
    for mapItem in self.mapItemList:
      if mapItem.startAddr <= addr and addr <= mapItem.endAddr:
        return mapItem
      elif addr < mapItem.startAddr:
        return None

  def printMemDict(self):
    print "add mem available:\n"
    for (addr, value) in self.memDict.items():
      print hex(addr) + ": " + hex(value)
      for location in self.locationsOfAddr(addr):
        print location

  def printAllThreadInfos(self):
    # self.printMemDict()
    for threadInfo in self.threadInfoList:
      print "\n\n\n>>>>> tid: " + threadInfo.tid
      print "\n\n"
      # self.printRegRefer(threadInfo)
      for btFrame in threadInfo.btFrameList:
        self.PrintThreadBt(btFrame)
      self.printThreadCodeAround(threadInfo)

  def storeCodeArounds(self, threadInfo):
    MkdirSafely(tool.CODE_AROUND_DIR)
    for (reg, codeAroundBlock) in threadInfo.blocks.codeAroundBlockDict.items():
      (codeAroundStartAddr, bytes) = BytesFromLines(self.linesOfBlock(codeAroundBlock))
      storeFileName = tool.CODE_AROUND_DIR + threadInfo.tid + "-" + reg + "-around"
      storeFile = open(storeFileName, "wb")
      storeFile.write(bytearray(bytes))
      threadInfo.codeAroundFileDict[reg] = (int(codeAroundStartAddr, 16), storeFileName)
    for (reg, memoryNearBlock) in threadInfo.blocks.memoryNearBlockDict.items():
      regInt = threadInfo.regDict[reg]
      mapItem = self.findAddrInMaps(regInt)
      if mapItem and (mapItem.accessMod & 1):
        (codeAroundStartAddr, bytes) = BytesFromLines(self.linesOfBlock(memoryNearBlock))
        storeFileName = tool.CODE_AROUND_DIR + threadInfo.tid + "-" + reg + "-around"
        storeFile = open(storeFileName, "wb")
        storeFile.write(bytearray(bytes))
        threadInfo.codeAroundFileDict[reg] = (int(codeAroundStartAddr, 16), storeFileName)

  def saveAddrValueInMemDict(self, startAddr, valueHex, location):
    bytes = BytesLE([valueHex])
    addr = startAddr
    for byte in bytes:
      self.memDict[addr] = byte
      self.recordAddrLocation(addr, location)
      addr = addr + 1
    # if not addr in self.memDict:
    #   self.memDict[addr] = (value, [location])
    # else:
    #   (savedValue, locationList) = self.memDict[addr]
    #   if value == savedValue:
    #     if not location in locationList:
    #       locationList.append(location)
    #   else:
    #     raise Exception("a address has two different value!!")

  def recordAddrLocation(self, addr, location):
    for locationItem in self.locationList:
      if locationItem.location == location:
        if addr < locationItem.startAddr:
          locationItem.startAddr = addr
        elif addr > locationItem.endAddr:
          locationItem.endAddr = addr
        return
    # not found location
    newLocationItem = LocationItem()
    newLocationItem.startAddr = addr
    newLocationItem.endAddr = addr
    newLocationItem.location = location
    self.locationList.append(newLocationItem)

  def locationsOfAddr(self, addr):
    locations = []
    for locationItem in self.locationList:
      if locationItem.startAddr <= addr and addr <= locationItem.endAddr:
        locations.append(locationItem.location)
    mapItem = self.findAddrInMaps(addr)
    if mapItem and mapItem.file:
      locations.append(mapItem.file + " in maps")
    return locations

  def findAddrsForValue(self, valueExpect, byteLen = 0):
    addrs = []
    if not byteLen:
      maxHex = "f" * 8
      byteLen = 4
      while valueExpect >= int(maxHex, 16):
        maxHex = maxHex * 2
        byteLen = byteLen * 2
    for (addr, value) in self.memDict.items():
      if self.getValueForAddrAndByteLen(addr, byteLen) == valueExpect:
        addrs.append(addr)
    return addrs

  def getValueForAddrAndByteLen(self, startAddr, byteLen = 0):
    if not byteLen:
      byteLen = int(WidthForArch()) / 2
    byteList = []
    for offset in range(0, byteLen):
      addr = startAddr + offset
      if addr in self.memDict:
        byteList.append(self.memDict[addr])
      else:
        break
    return int(INIT_STR.join('{:02x}'.format(x) for x in reversed(byteList)), 16)

  def buildMemDict(self):
    for threadInfo in self.threadInfoList:
      stackMemPatC = re.compile("([a-f0-9]" + self.width + ")\\s*?([a-f0-9]" + self.width + ")")
      for line in self.linesOfBlock(threadInfo.blocks.stackBlock):
        stackMemMatch = stackMemPatC.search(line)
        if stackMemMatch:
          addr = int(stackMemMatch.group(1), 16)
          valueHex = stackMemMatch.group(2)
          location = "stack " + threadInfo.tid
          self.saveAddrValueInMemDict(addr, valueHex, location)

      memPatC = re.compile("([a-f0-9]" + self.width + "|-" + self.width + ")")
      for (reg, memoryNearBlock) in threadInfo.blocks.memoryNearBlockDict.items():
        for line in self.linesOfBlock(memoryNearBlock):
          memMatchList = memPatC.findall(line)
          if memMatchList:
            addr = int(memMatchList[0], 16)
            for memWord in memMatchList[1:]:
              noMapWord = "-" * len(memWord)
              if noMapWord != memWord:
                valueHex = memWord
                location = "memory near " + reg + " of " + threadInfo.tid
                self.saveAddrValueInMemDict(addr, valueHex, location)
              addr = addr + len(memWord) / 2

      for (reg, codeAroundBlock) in threadInfo.blocks.codeAroundBlockDict.items():
        for line in self.linesOfBlock(codeAroundBlock):
          memMatchList = memPatC.findall(line)
          if memMatchList:
            addr = int(memMatchList[0], 16)
            for memWord in memMatchList[1:]:
              noMapWord = "-" * len(memWord)
              if noMapWord != memWord:
                valueHex = memWord
                location = "code around " + reg + " of " + threadInfo.tid
                self.saveAddrValueInMemDict(addr, valueHex, location)
              addr = addr + len(memWord) / 2

  def generateReport(self):
    print("generate report...")
    self.reportSummary()
    self.reportCrashThread()
    if DETAIL:
      self.reportOtherThreads()
    self.reportLogs()
    self.reportMap()

  def reportSummary(self):
    PrintlnToReport("<<SUMMARY>>")
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(" DEVICE:".ljust(40) + self.brand + " " + self.device)
    PrintlnToReport(" BUILD NUMBER:".ljust(40) + self.buildNumber + " " + self.variant + " " + self.key)
    PrintlnToReport(" ANDROID VERSION:".ljust(40) + self.andVersion)
    PrintlnToReport("")
    PrintlnToReport(" PROCESS:".ljust(40) + self.threadInfoList[0].pname)
    PrintlnToReport(" PID:".ljust(40) + self.threadInfoList[0].pid)
    PrintlnToReport("")
    PrintlnToReport(" CRASH THREAD:".ljust(40) + self.threadInfoList[0].tname)
    PrintlnToReport(" TID:".ljust(40) + self.threadInfoList[0].tid)
    PrintlnToReport("")
    PrintlnToReport(" SIGNAL:".ljust(40) + self.signame + " (" + self.signum + ")")
    PrintlnToReport(" SIGCODE:".ljust(40) + self.sigcodeName + " (" + self.sigcode + ")")
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport("\n\n")

  def reportLogs(self):
    PrintlnToReport("<<LOGS>>")
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    for logBlock in self.logBlockList:
      logs = INIT_STR
      for line in self.linesOfBlock(logBlock):
        logs = logs + line
      PrintlnToReport(logs)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport("\n\n")


  def formatHexWidth(self, hexStr):
    if self.arch == "arm":
      width = 8
    else:
      width = 16
    hexPrefix = "0x"
    zeroWidth = width - len(hexStr) + len(hexPrefix)
    return hexPrefix + "0" * zeroWidth + hexStr[len(hexPrefix):]

  def getRegReferDeeply(self, addr):
    lineMaxCount = 1
    result = INIT_STR
    while addr and addr in self.memDict:
      if not lineMaxCount:
        result = result + "\n" + " ".ljust(10)
        lineMaxCount = 1
      lineMaxCount = lineMaxCount - 1
      value = self.memDict[addr]
      result = result + "-->".ljust(10) + self.formatHexWidth(hex(value)).ljust(20) + str(self.locationsOfAddr(addr))
      if addr == value:
        break
      else:
        addr = value
    return result

  def getRegValueAllLocation(self, valueExpect):
    if not valueExpect:
      return None
    lineMaxCount = 1
    result = INIT_STR
    addrList = self.findAddrsForValue(valueExpect)
    for addr in addrList:
      if not lineMaxCount:
        result = result + "\n" + " ".ljust(10)
        lineMaxCount = 1
      lineMaxCount = lineMaxCount - 1
      result = result + "found in ".ljust(10) + self.formatHexWidth(hex(addr)).ljust(20) + str(self.locationsOfAddr(addr))
    return result

  def reportRegsOfThread(self, threadInfo):
    PrintlnToReport(" REGISTERS:")
    regList = self.registerNames[tool.ARCH].split("|")
    for reg in regList:
      regValueInt = threadInfo.regDict[reg]
      regValue = hex(regValueInt)
      PrintlnToReport(DEVIDED_LINE)
      PrintlnToReport(" " + reg.ljust(9) + self.formatHexWidth(regValue))

      if DETAIL:
        refers = self.getRegReferDeeply(regValueInt)
        if refers:
          PrintlnToReport(" refers:".ljust(10) + refers)
        refered = self.getRegValueAllLocation(regValueInt)
        if refered:
          PrintlnToReport(" refered:".ljust(10) + refered)
    PrintlnToReport(DEVIDED_LINE)

  def reportBackTrace(self, threadInfo):
    PrintlnToReport("\n\n\n")
    PrintlnToReport("=" * 100)
    PrintlnToReport(" BACKTRACE:")
    for btFrame in threadInfo.btFrameList:
      self.reportBtFrame(btFrame)

  def reportBtFrame(self, btFrame):
    arrow = "v------>"
    if self.arch == "arm64" or self.arch == "mips64" or self.arch == "x86_64":
      arrow = "v-------------->"

    (frame, addrKey) = btFrame
    (lib, addrHexInt) = addrKey
    addr = hex(addrHexInt)

    PrintlnToReport("\n\n<#" + frame + ">")
    PrintlnToReport(DEVIDED_LINE_LAYER)

    if tool.IsOatFile(lib):
      oatInfo = self.fetchAddrInfo(addrKey)
      if oatInfo:
        (location, clazz, linesMethod) = oatInfo
        exeOffsetHexInt = self.oatFileOffsetDict[lib]
        addr = hex(tool.StripPC(addrHexInt + exeOffsetHexInt))
        PrintlnToReport(" " + addr + " " + lib)
        PrintlnToReport(DEVIDED_LINE)
        PrintlnToReport(" location: " + location)
        PrintlnToReport(DEVIDED_LINE)

        dexPcPat = "^\\s*suspend point dex PC:(.*)"
        dexPcPatC = re.compile(dexPcPat)
        instPcPatC = re.compile("^\\s*0x0*" + addr[2:] + ":")
        dexPc = INIT_STR
        # search pc and dex pc
        for line in linesMethod:
          dexPcMatch = dexPcPatC.search(line)
          if dexPcMatch:
            dexPc = dexPcMatch.group(1).strip()
          else:
            instPcMatch = instPcPatC.search(line)
            if instPcMatch:
              break

        if dexPc:
          PrintlnToReport(" class: " + clazz)
          PrintlnToReport(DEVIDED_LINE)
          dexPcMatched = INIT_STR
          dexCodePatC = re.compile("^\\s*" + dexPc + ":")
          PrintlnToReport(" full method (\'==>\' indicate the crash line of java):")
          for line in linesMethod:
            prefix = "   "
            if not dexPcMatched:
              dexPcMatched = re.search(dexPcPat + dexPc, line)
              if dexPcMatched:
                prefix = "->>"
              else:
                dexCodeMatch = dexCodePatC.search(line)
                if dexCodeMatch:
                  prefix = "==>"
            else:
              instPcMatch = instPcPatC.search(line)
              if instPcMatch:
                prefix = "-->"
            PrintlnToReport(prefix + line)
        else:
          PrintlnToReport(" Dex pc no found. This may be a native method.")
        PrintlnToReport(DEVIDED_LINE_LAYER)
      else:
        PrintlnToReport(" " + addr + " " + lib)
        PrintlnToReport(DEVIDED_LINE_LAYER)
    else:
      (addr2lineLayers, (funcSymbol, instList)) = self.fetchAddrInfo(addrKey)
      if addr2lineLayers and BTX_NEED_SC:
        layerCount = len(addr2lineLayers) - 1
        for (symbol, source) in addr2lineLayers:
          if layerCount > 0:
            layerCount = layerCount - 1
            vaddr = arrow
          else:
            vaddr = addr
          PrintlnToReport(" " + vaddr + " " + symbol + "  at  " + lib)
          PrintlnToReport(DEVIDED_LINE)
          PrintlnToReport(" source line: " + source)
          PrintlnToReport(DEVIDED_LINE_LAYER)
      else:
        PrintlnToReport(" " + addr + " " + lib)
        PrintlnToReport(DEVIDED_LINE_LAYER)
      if funcSymbol and BTX_NEED_ASM:
        PrintlnToReport(" asm code around " + funcSymbol)
        for (offset, inst) in instList:
          if hex(tool.StripPC(int(addr, 16)))[2:] == offset.strip():
            prefix = "==>"
          else:
            prefix = "   "
          PrintlnToReport(prefix + offset + ":" + inst)
        PrintlnToReport(DEVIDED_LINE_LAYER)


  def reportCodeAround(self, threadInfo):
    if not threadInfo.codeAroundFileDict:
      return
    PrintlnToReport("\n\n")
    PrintlnToReport("=" * 100)
    PrintlnToReport(" CODE AROUND:\n\n")
    for (reg, (codeAroundStartAddr, fileName)) in threadInfo.codeAroundFileDict.items():
      commonPrefix = " " + len(reg) * " " + "   "
      startAddrHexInt = codeAroundStartAddr
      regValue = threadInfo.regDict[reg]
      instList = tool.CallObjdumpForSetWithDataFile(fileName, tool.IsThumb(regValue))
      PrintlnToReport(DEVIDED_LINE_LAYER)
      PrintlnToReport("code around " + reg + ":")
      mapItem = self.findAddrInMaps(regValue)
      if mapItem:
        PrintlnToReport(DEVIDED_LINE)
        PrintlnToReport(mapItem.file)
      PrintlnToReport(DEVIDED_LINE)
      for (offset, inst) in instList:
        offsetHexInt = int(offset, 16)
        absoluteAddrHexInt = startAddrHexInt + offsetHexInt
        if tool.StripPC(regValue) == absoluteAddrHexInt:
          prefix = " " + reg + "=> "
        else:
          prefix = commonPrefix
        PrintlnToReport(prefix + hex(absoluteAddrHexInt) + ":" + inst)
      PrintlnToReport(DEVIDED_LINE_LAYER)
      PrintlnToReport("\n\n\n")

  def reportCrashThread(self):
    crashThread = self.threadInfoList[0]

    PrintlnToReport("<<!!CRASH THREAD!!>>")
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)

    PrintlnToReport(" CRASH THREAD:".ljust(40) + crashThread.tname)
    PrintlnToReport(" TID:".ljust(40) + crashThread.tid)
    PrintlnToReport("")

    PrintlnToReport(DEVIDED_LINE)
    PrintlnToReport(" FAULT ADDR:".ljust(40) + self.faultAddr)
    if DETAIL and not "-" in self.faultAddr:
      PrintlnToReport(DEVIDED_LINE)
      regValueInt = int(self.faultAddr, 16)
      refers = self.getRegReferDeeply(regValueInt)
      if refers:
        PrintlnToReport(" refers:".ljust(10) + refers)
      refered = self.getRegValueAllLocation(regValueInt)
      if refered:
        PrintlnToReport(" refered:".ljust(10) + refered)
    PrintlnToReport(DEVIDED_LINE)

    PrintlnToReport("")
    self.reportRegsOfThread(crashThread)
    PrintlnToReport("")
    self.reportBackTrace(crashThread)
    PrintlnToReport("")
    self.reportCodeAround(crashThread)

    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport("\n\n\n")

  def reportOtherThreads(self):
    for threadInfo in self.threadInfoList[1:]:
      threadNameTag = ""
      if threadInfo.tid == threadInfo.pid:
        threadNameTag = "MAIN "
      threadNameTag = "<<" + threadNameTag + "THREAD " + threadInfo.tid + ">>"
      PrintlnToReport(threadNameTag)
      PrintlnToReport(DEVIDED_LINE_FRAME)
      PrintlnToReport(DEVIDED_LINE_FRAME)

      PrintlnToReport(" THREAD:".ljust(40) + threadInfo.tname)
      PrintlnToReport(" TID:".ljust(40) + threadInfo.tid)
      PrintlnToReport("")
      self.reportRegsOfThread(threadInfo)
      PrintlnToReport("")
      self.reportBackTrace(threadInfo)
      PrintlnToReport("")
      self.reportCodeAround(threadInfo)


      PrintlnToReport(DEVIDED_LINE_FRAME)
      PrintlnToReport(DEVIDED_LINE_FRAME)
      PrintlnToReport("\n\n\n")

  def lineFromMapItem(self, mapItem):
    line = "\t"
    line += self.formatHexWidth(hex(mapItem.startAddr)).ljust(24)
    line += self.formatHexWidth(hex(mapItem.endAddr)).ljust(24)
    modStr = INIT_STR
    mod = mapItem.accessMod
    isR = mod & 4
    isW = mod & 2
    isX = mod & 1
    if isR:
      modStr = modStr + "r"
    else:
      modStr = modStr + "-"
    if isW:
      modStr = modStr + "w"
    else:
      modStr = modStr + "-"
    if isX:
      modStr = modStr + "x"
    else:
      modStr = modStr + "-"
    line += modStr.ljust(8)
    line += mapItem.file
    return line

  def reportMap(self):
    PrintlnToReport("\n\n<<MAP>>")
    PrintlnToReport(DEVIDED_LINE_FRAME)
    PrintlnToReport(DEVIDED_LINE_FRAME)
    for mapItem in self.mapItemList:
      PrintlnToReport(self.lineFromMapItem(mapItem))

  def __init__(self, lines):
    DebugPrint("Construct TombCore...")

    # members start
    self.lines = lines

    self.arch = tool.ARCH
    self.brand = INIT_STR
    self.product = INIT_STR
    self.device = INIT_STR
    self.andVersion = INIT_STR
    self.buildId = INIT_STR
    self.buildNumber = INIT_STR
    self.variant = INIT_STR
    self.key = INIT_STR

    self.signum = INIT_STR
    self.signame = INIT_STR
    self.sigcode = INIT_STR
    self.sigcodeName = INIT_STR
    self.faultAddr = INIT_STR
    self.threadInfoList = []

    self.addrInfoDict = dict()
    self.memDict = dict()
    self.oatAddrLibDict = dict()
    self.oatFileOffsetDict = dict()
    self.logBlockList = []
    self.locationList = []
    # members end

    self.preProcess()

    headPat = "^pid: (?P<pid>[0-9]+), tid: (?P<tid>[0-9]+), name: (?P<tname>.*?)(>>> (?P<pname>.*) <<<)?$"
    signalPat = "^signal (?P<signum>\\d+) \((?P<signame>\\w+)\), code (?P<sigcode>\\S+) \((?P<sigcodeName>\\w+)\)," \
              + " fault addr (?P<faultAddr>(0x)?([0-9a-fA-F]|-)+)$"
    registPat = "\\b(?P<regName>" + self.registerNames[self.arch] + ")\\b +?(?P<regValue>[0-9a-f]" + self.width + ")"
    btStartPat = "^backtrace:"
    stackStartPat = "^stack:"
    mapStartPat = "^memory map:"
    memoryNearStartPat = "^memory near (" + self.registerNames[self.arch] + "):"
    codeAroundStartPat = "^code around (" + self.registerNames[self.arch] + "):"
    blockEndPat = "^\n$"
    logStartPat = "(tail end of log)|(log system)|(log main)"

    threadBlocksList = []
    mapBlock = None
    currentTb = None
    currentB = None
    for index, line in enumerate(lines):
      if MatchLineByPat(line, headPat):
        self.endPrevBlock(currentB, index)
        DebugPrint("match head")
        DebugPrint(threadBlocksList)
        currentTb = ThreadBlocks()
        currentB = currentTb.headBlock
        currentB.startIndex = index
        threadBlocksList.append(currentTb)
      elif MatchLineByPat(line, btStartPat):
        self.endPrevBlock(currentB, index)
        DebugPrint("match bt")
        currentB = currentTb.backtraceBlock
        currentB.startIndex = index
      elif MatchLineByPat(line, stackStartPat):
        self.endPrevBlock(currentB, index)
        DebugPrint("match stack")
        currentB = currentTb.stackBlock
        currentB.startIndex = index
      elif MatchLineByPat(line, mapStartPat):
        self.endPrevBlock(currentB, index)
        DebugPrint("match map")
        mapBlock = Block()
        currentB = mapBlock
        currentB.startIndex = index
      elif MatchLineByPat(line, memoryNearStartPat):
        self.endPrevBlock(currentB, index)
        reg = MatchLineByPat(line, memoryNearStartPat).group(1)
        DebugPrint("match memory near " + reg)
        currentB = Block()
        currentB.startIndex = index
        currentTb.memoryNearBlockDict[reg] = currentB
      elif MatchLineByPat(line, codeAroundStartPat):
        self.endPrevBlock(currentB, index)
        reg = MatchLineByPat(line, codeAroundStartPat).group(1)
        DebugPrint("code around near " + reg)
        currentB = Block()
        currentB.startIndex = index
        currentTb.codeAroundBlockDict[reg] = currentB
      elif MatchLineByPat(line, logStartPat):
        self.endPrevBlock(currentB, index)
        DebugPrint("match logs")
        currentB = Block()
        currentB.startIndex = index
        self.logBlockList.append(currentB)
      elif MatchLineByPat(line, blockEndPat):
        self.endPrevBlock(currentB, index)
        currentB = None
      else:
        pass

    self.endPrevBlock(currentB, len(lines))

    self.dump()

    DumpThreadBlocksList(threadBlocksList, self.logBlockList, mapBlock)

    mapPat = "^\\s*(?P<startAddr>([0-9a-fA-F])" + self.width + ")-(?P<endAddr>([0-9a-fA-F])" + self.width + ")\\s*" \
               + "(?P<access>(r|w|x|-){3})" + "(\\s+[0-9a-fA-F]+)+" + "\\s+(?P<file>\\S*)(\\s+.*)?"

    self.mapItemList = []
    for line in self.linesOfBlock(mapBlock):
      line = line.replace("\'", "", 2)
      mapLineMatch = re.search(mapPat, line)
      if mapLineMatch:
        mapItem = MapItem()
        mapItem.startAddr = int(mapLineMatch.group("startAddr"), 16)
        mapItem.endAddr = int(mapLineMatch.group("endAddr"), 16)
        mapItem.file = str(mapLineMatch.group("file"))
        access = str(mapLineMatch.group("access"))
        accessMod = 0
        if access[0] == "r":
          accessMod = accessMod + 4
        if access[1] == "w":
          accessMod = accessMod + 2
        if access[2] == "x":
          accessMod = accessMod + 1
        mapItem.accessMod = accessMod
        if not self.mapItemList:
          self.mapItemList.append(mapItem)
        else:
          # extend last map item or add new item
          if mapItem.file == self.mapItemList[-1].file and mapItem.accessMod == self.mapItemList[-1].accessMod:
            self.mapItemList[-1].endAddr = mapItem.endAddr
          else:
            self.mapItemList.append(mapItem)
      else:
        pass

    for line in self.linesOfBlock(threadBlocksList[0].headBlock):
      siginfoMatch = re.search(signalPat, line)
      if siginfoMatch:
        self.signum = siginfoMatch.group("signum")
        self.signame = siginfoMatch.group("signame")
        self.sigcode = siginfoMatch.group("sigcode")
        self.sigcodeName = siginfoMatch.group("sigcodeName")
        self.faultAddr = siginfoMatch.group("faultAddr")
        break

    for threadB in threadBlocksList:
      threadInfo = ThreadInfo()
      self.threadInfoList.append(threadInfo)
      regDict = threadInfo.regDict
      headMatch = re.search(headPat, self.lines[threadB.headBlock.startIndex])
      if headMatch:
        threadInfo.pid = headMatch.group("pid")
        threadInfo.tid = headMatch.group("tid")
        pname = headMatch.group("pname")
        if pname:
          threadInfo.pname = pname
        threadInfo.tname = headMatch.group("tname").rstrip()
      for line in self.linesOfBlock(threadB.headBlock):
        regMatchList = re.findall(registPat, line)
        for regTup in regMatchList:
          regName = regTup[0]
          regValueInt = int(regTup[1], 16)
          regDict[regName] = regValueInt
          self.recordAddrLocation(regValueInt, regName + " of " + threadInfo.tid)
      threadInfo.blocks = threadB

    for threadInfo in self.threadInfoList:
      self.parseBackTrace(threadInfo)
      self.storeCodeArounds(threadInfo)
    self.buildMemDict()

