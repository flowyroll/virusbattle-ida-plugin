"""Dictionary Cache with Signaling support

Returns:
    TYPE: Description
"""
from PySide import QtCore

class VBCache(QtCore.QObject):
    """Dictionary Cache class

    finishedUpdatingCache will be Signaled after each update to the cache
    """
    
    finishedUpdatingCache = QtCore.Signal(dict)
    def __init__(self):
        """Constructor for VBCache
        
        Returns:
            TYPE: VBCache
        """
        QtCore.QObject.__init__(self, None)
        self.cache = {}

    def update(self, key, value):
        """Update value of a key
        
        Args:
            key (object): Key
            value (object): value                
        """
        self.cache.update({
            key: value
        })
        self.finishedUpdatingCache.emit(value)

    def read(self, key):
        """Summary
        
        Args:
            key (TYPE): key of the cache to retreive
        
        Returns:
            TYPE: object
        """
        if key in self.cache:
            return self.cache[key]
        else:
            return None

    def readAll(self):
        """Retreive the whol Dictionary
        
        Returns:
            TYPE: Dict
        """
        return self.cache

    def clean(self):
        """Clean the cache
        
        """
        self.cache = {}