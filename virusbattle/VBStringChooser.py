from idaapi import *
from idautils import *
from idc import *

class VBStringChooser(Choose2):
    def __init__(self, binHash, strings, deflt=1):
        
        Choose2.__init__(self, "Strings for binary " + binHash,
            [ 
                ['RVA', 10 | Choose2.CHCOL_HEX], 
                ['String', 30 | Choose2.CHCOL_PLAIN],
                ['Binary hash', 30 | Choose2.CHCOL_PLAIN]
            ], Choose2.CH_MULTI )
   
        self.n = 0
        self.icon = 41
        self.deflt = deflt
        self.strings = strings
        self.hash = binHash
        self.populateItems()
        self.Show()

    def populateItems(self):
        self.items = []
        for x in self.strings:
            str = x[0]
            offsets = x[1]
            for offset in offsets:
                self.items.append([offset, str, self.hash])
        print self.items
           
    def OnClose(self):
        pass

    def OnSelectLine(self, n):
        print self.items[n]
        
    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.populateItems()
        return n