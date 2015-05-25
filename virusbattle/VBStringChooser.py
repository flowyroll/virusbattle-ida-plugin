from idaapi import *
from idautils import *
from idc import *

class VBStringChooser(Choose2):
    def __init__(self, binHash, strings, deflt=1):        
        title = 'Strings for binary ' + binHash
        Choose2.__init__(self, title.encode('ascii'),
            [ 
                ['RVA', 10 | Choose2.CHCOL_HEX], 
                ['String', 40 | Choose2.CHCOL_PLAIN],
                ['Binary hash', 30 | Choose2.CHCOL_PLAIN]
            ], Choose2.CH_MULTI )
   
        self.n = 0
        self.icon = 41
        self.deflt = deflt
        self.strings = strings
        self.binHash = binHash
        self.populateItems()   

    def populateItems(self):
        self.items = []
        for x in self.strings:
            s = x[0]
            offsets = x[1]
            for offset in offsets:
                self.items.append(
                    [
                        offset,#.encode('ascii','replace'),
                        s,#.encode('ascii','replace'),
                        self.binHash#.encode('ascii','replace')
                    ]
                )
           
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
        