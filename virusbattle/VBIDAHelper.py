"""Helper functions and wrappers

Returns:
    TYPE: Description
"""
from idaapi import *
from idc import *
from idautils import *
from hashlib import *


def getFilePath():
    """Get path of the binary related to the current IDB file
    
    Returns:
        TYPE: Str
    """
    return get_input_file_path()


def SHA1File(path):
    """Calculate SHA checksum of a file
    
    Args:
        path (TYPE): Path of the files
    
    Returns:
        TYPE: Str
    """
    with open(path, 'rb') as f:
        return sha1(f.read()).hexdigest()

def addressFromRVA(rva):
    return get_imagebase() + rva

def RVAFromAddress(address):
    return abs(address - get_imagebase())

def rgbTohex(rgb):
    return '0x%02x%02x%02x' % rgb

def setFunctionColor(ea, R, G, B):
    SetColor(ea, CIC_FUNC, int(rgbTohex((R, G, B)), 16))

def setFunctionComment(ea, cmt):
    set_func_cmt(get_func(ea), cmt, True)

def getFunctionComment(ea):
    return get_func_cmt(get_func(ea), True)

def delFunctionComment(ea):
    return del_func_cmt(get_func(ea), True)

def getFunctions():
    funcs = []
    for seg in Segments():
        for func in Functions(SegStart(seg), SegEnd(seg)):
            funcs.append(func)
    return funcs

def addMenuItem(root, title, hotkey, cb, *args):
    return add_menu_item(root, title, hotkey, 0, cb, args)

def currentFunctionRVA():
    return hex(abs(get_imagebase() - get_func(get_screen_ea()).startEA))

def getIDAPath():
    return idadir('idaq.exe')
