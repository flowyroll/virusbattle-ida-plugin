"""Asynchronous web service command
we need it to avoid the QT GUI from hang 

Returns:
    TYPE: Description
"""
from VBAPI import VBAPI
from PySide import QtCore

class VBAsyncCommand(QtCore.QObject, QtCore.QRunnable):
    """Asynchronous web service command class
    
    finishedProcessing is the Signal that will be emitted after completion
    of the Web request        
    """
    finishedProcessing = QtCore.Signal(dict)

    def __init__(self, command, *args):
        """Constructor for the Asynchronous command
        
        Args:
            command (Str): Name of the command
            *args: Variable number of args based on the command and optional
            parameters
        
        Returns:
            TYPE: VBAsyncCommand
        """
        self.command = command
        self.args = args
        QtCore.QObject.__init__(self, None)
        QtCore.QRunnable.__init__(self)

    def tryRun(self):
        """Try to run the configured command and in case of Exception return
        Exception message as a result
        
        Returns:
            TYPE: Dict
        """
        try:
            if self.command == 'register':
                result = VBAPI.register(self.args[0], self.args[1])                
            elif self.command == 'download':
                if len(self.args) > 3:
                    result = VBAPI.download(
                        self.args[0], self.args[1], self.args[2], self.args[3])
                else:
                    result = VBAPI.download(
                        self.args[0], self.args[1], self.args[2])            
            elif self.command == 'query':
                if len(self.args) > 1:
                    result = VBAPI.query(self.args[0], self.args[1])
                else:
                    result = VBAPI.query(self.args[0])            
            elif self.command == 'searchProcs':
                if len(self.args) > 3:
                    result = VBAPI.searchProcs(
                        self.args[0], self.args[1], self.args[2], self.args[3])
                elif len(self.args) == 3:
                    result = VBAPI.searchProcs(
                        self.args[0], self.args[1], self.args[2])
                else:
                    result = VBAPI.searchProcs(self.args[0], self.args[1])            
            elif self.command == 'searchBins':
                if len(self.args) > 3:
                    result = VBAPI.searchBins(
                        self.args[0], self.args[1], self.args[2], self.args[3])
                elif len(self.args) == 3:
                    result = VBAPI.searchBins(
                        self.args[0], self.args[1], self.args[2])
                else:
                    result = VBAPI.searchBins(self.args[0], self.args[1])            
            elif self.command == 'showProc':
                if len(self.args) > 3:
                    result = VBAPI.showProc(
                        self.args[0], self.args[1], self.args[2], self.args[3])
                else:
                    result = VBAPI.showProc(
                        self.args[0], self.args[1], self.args[2])            
            elif self.command == 'showBin':
                if len(self.args) > 2:
                    result = VBAPI.showBin(
                        self.args[0], self.args[1], self.args[2])
                else:
                    result = VBAPI.showBin(self.args[0], self.args[1])            
            elif self.command == 'upload':
                if len(self.args) > 4:
                    result = VBAPI.upload(
                        self.args[0], self.args[1], self.args[2], self.args[3], self.args[4])
                elif len(self.args) == 4:
                    result = VBAPI.upload(
                        self.args[0], self.args[1], self.args[2], self.args[3])
                elif len(self.args) == 3:
                    result = VBAPI.upload(
                        self.args[0], self.args[1], self.args[2])
                else:
                    result = VBAPI.upload(self.args[0], self.args[1])            
            elif self.command == 'reprocess':
                if len(self.args) > 2:
                    result = VBAPI.reprocess(
                        self.args[0], self.args[1], self.args[2])
                else:
                    result = VBAPI.reprocess(self.args[0], self.args[1])            
            elif self.command == 'avscans':
                if len(self.args) > 1:
                    result = VBAPI.avscans(self.args[0], self.args[1])
            elif self.command == 'behaviors':
                if len(self.args) > 1:
                    result = VBAPI.behaviors(self.args[0], self.args[1])
            elif self.command == 'pedata':
                if len(self.args) > 1:
                    result = VBAPI.pedata(self.args[0], self.args[1])

        except Exception as e:
            result = {
                'statuscode': 1,
                'message': e.message
            }

        return result

    def run(self):
        """Call `tryRun` and emit the Signal with available result from server 
        or Exception. This function will be called automatically by the nature 
        of QRunnable Interface after call to `start`
                
        """
        result = self.tryRun()
        self.finishedProcessing.emit(result)

    def start(self):
        """Start the Asynchronous task by passing this class to global thread 
        pool instance
                
        """
        QtCore.QThreadPool.globalInstance().start(self)

    def stop(self):
        """There is no way to stop a running Asynchronous task currently and it
        is not supported by QRunnable.
        
        """
        pass