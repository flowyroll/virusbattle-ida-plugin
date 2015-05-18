from idaapi import *
from idautils import *
from idc import *

class VBCustomChooser(Choose2):
    def __init__(self, title, cols, items, deflt=1):
        Choose2.__init__(self, title, 
            cols, Choose2.CH_MULTI )
        
        self.n = 0
        # self.icon = 41
        self.deflt = deflt
        self.items = items
        
    def OnClose(self):
        pass

    def OnSelectLine(self, n):
        print self.items[n]

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.items = items
        return n