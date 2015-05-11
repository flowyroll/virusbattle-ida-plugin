from idaapi import *
from idautils import *
from idc import *
import VBIDAHelper

class VBFunctionChooser(Choose2):
    def __init__(self, title, isMatchedProcs, matchedProcsCache, procId=None, deflt=1):
        if isMatchedProcs:
            Choose2.__init__(self, title, 
                [ 
                    ['RVA', 10 | Choose2.CHCOL_HEX], 
                    ['Name', 30 | Choose2.CHCOL_PLAIN],
                    ['Binary hash', 30 | Choose2.CHCOL_PLAIN]
                ], Choose2.CH_MULTI )
        else:
            Choose2.__init__(self, title, 
                [ 
                    ['Address', 10 | Choose2.CHCOL_HEX], 
                    ['Name', 30 | Choose2.CHCOL_PLAIN],                    
                ], Choose2.CH_MULTI)

        self.n = 0
        self.icon = 41
        self.deflt = deflt
        self.isMatchedProcs = isMatchedProcs
        self.procId = procId
        self.matchedProcsCache = matchedProcsCache
        self.populateItems()        

    def populateItems(self):
        self.items = []        
        if self.isMatchedProcs:
            matchedProcs = self.matchedProcsCache.read(self.procId)
            if matchedProcs is not None:
                for mProcs in matchedProcs:
                    binHash, rva = mProcs['proc_id'].split('/')
                    self.items.append([rva, mProcs['procName'], binHash])
            else:              
                self.items = [['', 'No Matched Procedure for this address', '']]  
                
        else:
            procsWithSim = self.matchedProcsCache.readAll()
            for proc in procsWithSim:                
                ea = VBIDAHelper.addressFromRVA(int(proc.split('/')[1], 16))
                self.items.append([hex(ea), GetFunctionName(ea)])
        
    def OnClose(self):
        pass

    def OnSelectLine(self, n):
        if self.isMatchedProcs:
            print self.items[n]
        else:
            Jump(int(self.items[n][0], 16))

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.populateItems()
        return n