"""Main widget GUI Interface

"""
from PySide import QtCore, QtGui
from VBUI import Ui_frmVirusBattle
from VBProfile import VBProfile
from VBAsyncCommand import VBAsyncCommand
from VBCache import VBCache
from VBFunctionChooser import VBFunctionChooser
import VBIDAHelper
import os
from ctypes import *

class VBMainWidget(QtGui.QWidget):
    def __init__(self, parent=None):
        super(VBMainWidget, self).__init__(parent)
        self.ui = Ui_frmVirusBattle()
        self.ui.setupUi(self)
        self.APIKey = None        
        
        self.initCaches()
        self.initSignals()

        VBIDAHelper.addMenuItem('View/', '[VB] Matched Procs', 'Alt-Shift-V', 
            self.menuItemMatchedProcsTriggered, self.matchedProcsCache)
        
        self.currentDir = os.path.dirname(os.path.realpath(__file__))
        self.openedFilePath = VBIDAHelper.getFilePath()
        self.openedFileHash = ''
        try:
            self.openedFileHash = VBIDAHelper.SHA1File(self.openedFilePath)
        except:
            pass
        if self.openedFileHash != '':
            self.ui.lblOpenFileHash.setText('Current file hash: %s' % self.openedFileHash)
        else:
            self.openedFilePath = ''
            self.ui.lblOpenFileHash.setText('Current file could be not found.')

        self.loadListProfiles()
   
    def initCaches(self):
        self.binaryListCache = VBCache()
        self.binaryListCache.finishedUpdatingCache.connect(self.binaryListUpdated)
        self.binaryInfoCache = VBCache()
        self.binaryInfoCache.finishedUpdatingCache.connect(self.binaryInfoUpdated)
        self.matchedBinsCache = VBCache()
        self.matchedBinsCache.finishedUpdatingCache.connect(self.MatchedBinariesUpdated)
        self.matchedProcsCache = VBCache()
        self.matchedProcsCache.finishedUpdatingCache.connect(self.MatchedProcsUpdated)
        self.juiciesCache = VBCache()
        self.juiciesCache.finishedUpdatingCache.connect(self.juiceUpdated)
        self.juiceIndividualCache = VBCache()
        self.juiceIndividualCache.finishedUpdatingCache.connect(self.juiceIndividualUpdated)
        self.rvaProcessingList = []
        self.rvaProcessing = None

    def initSignals(self):
        self.ui.btnRegister.clicked.connect(self.buttonClicked)
        self.ui.btnRemoveProfile.clicked.connect(self.buttonClicked)
        self.ui.btnSaveProfile.clicked.connect(self.buttonClicked)
        self.ui.btnReloadBinaries.clicked.connect(self.buttonClicked)
        self.ui.btnRefreshBinary.clicked.connect(self.buttonClicked)
        self.ui.btnDownloadChildBinary.clicked.connect(self.buttonClicked)
        self.ui.btnDownloadBinary.clicked.connect(self.buttonClicked)
        self.ui.btnReloadSimilarBins.clicked.connect(self.buttonClicked)
        self.ui.btnDownloadMatchedBin.clicked.connect(self.buttonClicked)
        self.ui.btnReloadMatchedProcs.clicked.connect(self.buttonClicked)
        self.ui.btnHighlightColorChooser.clicked.connect(self.buttonClicked)
        self.ui.btnRemoveHighlights.clicked.connect(self.buttonClicked)
        self.ui.btnHighlightAllProcs.clicked.connect(self.buttonClicked)
        self.ui.btnShowProcsWithSim.clicked.connect(self.buttonClicked)
        self.ui.btnShowMatchedProcs.clicked.connect(self.buttonClicked)
        self.ui.btnMatchedLeftProcMoreInfo.clicked.connect(self.buttonClicked)
        self.ui.btnMatchedRightProcMoreInfo.clicked.connect(self.buttonClicked)
        self.ui.btnShowChild.clicked.connect(self.buttonClicked)

        self.ui.btnShowAPIKey.pressed.connect(self.showAPIKey)
        self.ui.btnShowAPIKey.released.connect(self.hideAPIKey)


        self.ui.listProfiles.currentItemChanged.connect(self.listProfileItemChanged)
        self.ui.listBins.currentItemChanged.connect(self.listBinsItemChanged)
        self.ui.listChildren.currentItemChanged.connect(self.listChildrenItemChanged)
        self.ui.listProcsWithSim.currentItemChanged.connect(self.listProcsWithSimItemChanged)
        self.ui.listMatchedProcs.currentItemChanged.connect(self.listMatchedProcsItemChanged)
        self.ui.listMatchedBins.currentItemChanged.connect(self.listMatchedBinsItemChanged)

        self.ui.toolBox.currentChanged.connect(self.toolBoxCurrentChanged)
        self.ui.tabWidgetVB.currentChanged.connect(self.tabWidgetVBChanged)
        
        self.ui.editAPIKey.textChanged.connect(self.editAPIKeyTextChanged)
        # self.ui.editMatchedLeftProcRVA.textChanged.connect(self.editMatchedLeftProcRVATextChanged)
        # self.ui.editMatchedRightProcRVA.textChanged.connect(self.editMatchedRightProcRVATextChanged)

    def showAPIKey(self):
        self.ui.editAPIKey.setEchoMode(QtGui.QLineEdit.Normal)
        self.ui.btnShowAPIKey.setText('Hide')

    def hideAPIKey(self):
        self.ui.editAPIKey.setEchoMode(QtGui.QLineEdit.PasswordEchoOnEdit)
        self.ui.btnShowAPIKey.setText('Show')

    def menuItemMatchedProcsTriggered(*args):        
        rvaStr = str(VBIDAHelper.currentFunctionRVA())
        args[0].openMatchedProcsChooser(rvaStr)
        
    def status(self, text, color):
        self.ui.lblStatus.setStyleSheet("QLabel { color : %s; }" % color)
        self.ui.lblStatus.setText(str(text))

    def notifyStatus(self, result):
        if 'statuscode' in result:
            if result['statuscode'] == 1:
                self.status(result['message'], 'red')
            if result['statuscode'] == 0:
                self.status(result['message'], 'green')
        else:
            print 'Network Error!'

    def waitCursor(self, active):
        if active:
            QtGui.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        else:
            QtGui.QApplication.restoreOverrideCursor()

    def loadListProfiles(self):
        self.ui.listProfiles.clear()
        profiles = VBProfile.loadAll()
        for profile in profiles:
            self.ui.listProfiles.addItem(profile.config['Name'])

    def editAPIKeyTextChanged(self):
        self.APIKey = self.ui.editAPIKey.text().strip()

    def registerFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        self.ui.btnRegister.setEnabled(True)

    def registerButtonClicked(self):
        email = self.ui.editEmail.text().strip()
        name = self.ui.editName.text().strip()
        if email == '':
            self.notifyStatus({
                'statuscode': 1,
                'message': 'Email Address field is empty'
            })
            self.ui.editEmail.setFocus()
            return

        if name == '':
            self.notifyStatus({
                'statuscode': 1,
                'message': 'Name field is empty'
            })
            self.ui.editName.setFocus()
            return

        self.waitCursor(True)
        self.ui.btnRegister.setEnabled(False)
        cmd = VBAsyncCommand('register', email, name)
        cmd.finishedProcessing.connect(self.registerFinished)
        self.status('Registering...', 'black')
        cmd.start()

    def saveProfileButtonClicked(self):
        profileName = self.ui.editProfileName.text().strip()
        if profileName == '':
            self.notifyStatus({
                'statuscode': 1,
                'message': 'Profile Name field is empty'
            })

            self.ui.editProfileName.setFocus()
            return

        profile = VBProfile(
            profileName,
            self.ui.editAPIKey.toPlainText().strip(),
            self.ui.editHighlightCaption.toPlainText().strip(),
            self.ui.btnHighlightColorChooser.styleSheet(),
            self.ui.boxThreshold.value(),
            True if self.ui.checkUpperHalf.checkState() == QtCore.Qt.CheckState.Checked else False,
            True if self.ui.checkNoLibProc.checkState() == QtCore.Qt.CheckState.Checked else False
        )
        result = profile.save()
        self.loadListProfiles()
        listWidget = self.ui.listProfiles
        listWidget.setCurrentItem(listWidget.item(listWidget.count() - 1))
        self.notifyStatus(result)

    def removeProfileButtonClicked(self):
        if self.ui.listProfiles.currentItem() is None:
            self.notifyStatus({
                'statuscode': 1,
                'message': 'No profile selected'
            })
            return

        profile = VBProfile.load(self.ui.listProfiles.currentItem().text())
        if type(profile) is not VBProfile:
            self.notifyStatus(profile)
            return
        result = profile.remove()
        self.loadListProfiles()
        if result['statuscode'] == 0:
            self.ui.btnRemoveProfile.setEnabled(False)
        self.notifyStatus(result)

    def cleanCaches(self):
        self.binaryInfoCache.clean()
        self.binaryListCache.clean()
        self.matchedBinsCache.clean()
        self.matchedProcsCache.clean()
        self.juiciesCache.clean()
        self.juiceIndividualCache.clean()

    def loadProfile(self):
        if self.ui.listProfiles.currentItem() is None:
            self.notifyStatus({
                'statuscode': 1,
                'message': 'No profile selected'
            })
            return

        profile = VBProfile.load(self.ui.listProfiles.currentItem().text())
        if type(profile) is not VBProfile:
            self.notifyStatus(profile)
            return

        cfg = profile.config
        self.ui.editProfileName.setText(cfg['Name'])
        self.ui.editAPIKey.setText(cfg['APIKey'])
        self.ui.editHighlightCaption.setText(cfg['HighlightCaption'])        
        self.ui.btnHighlightColorChooser.setStyleSheet(cfg['HighlightColor'])
        self.ui.boxThreshold.setValue(cfg['Threshold'])
        self.ui.checkUpperHalf.setCheckState(QtCore.Qt.CheckState.Checked if cfg['Upperhalf']
                                             else QtCore.Qt.CheckState.Unchecked)

        self.ui.checkNoLibProc.setCheckState(QtCore.Qt.CheckState.Checked if cfg['NoLibProc']
                                             else QtCore.Qt.CheckState.Unchecked)

        self.notifyStatus({
            'statuscode': 0,
            'message': 'Profile loaded successfully'
        })
        self.cleanCaches()

    def buttonClicked(self):
        sender = self.sender()
        btnName = sender.objectName()[3:]
        if btnName == 'Register':
            self.registerButtonClicked()
        elif btnName == 'SaveProfile':
            self.saveProfileButtonClicked()
        elif btnName == 'RemoveProfile':
            self.removeProfileButtonClicked()
        elif btnName == 'ReloadBinaries':
            self.queryAll()
        elif btnName == 'RefreshBinary':
            self.reprocess(self.ui.listBins.currentItem().text())
        elif btnName == 'DownloadBinary':
            if self.ui.listBins.currentItem() is not None:
                self.download(self.ui.listBins.currentItem().text(), False)
        elif btnName == 'DownloadChildBinary':
            if self.ui.listChildren.currentItem() is not None:
                self.download(self.ui.listChildren.currentItem().text(), True)
        elif btnName == 'ReloadSimilarBins':
            self.reloadSimilarBinsClicked()
        elif btnName == 'DownloadMatchedBin':
            hash = self.ui.listMatchedBins.currentItem().text()
            if hash != '':
                self.download(hash, False)
        elif btnName == 'ReloadMatchedProcs':
            self.ReloadMatchedProcsClicked()
        elif btnName == 'HighlightColorChooser':
            color = QtGui.QColorDialog.getColor()
            css = 'background-color: rgb(%s, %s, %s);'%(
                str(color.red()), str(color.green()), str(color.blue()))
            self.ui.btnHighlightColorChooser.setStyleSheet(css)
        elif btnName == 'RemoveHighlights':
            funcs = VBIDAHelper.getFunctions()            
            for func in funcs:
                VBIDAHelper.delFunctionComment(func)
                VBIDAHelper.setFunctionColor(func, 0xff, 0xff, 0xff)
            
            self.notifyStatus({
                'statuscode': 0,
                'message': 'Highlights has been removed'
            })
        elif btnName == 'HighlightAllProcs':
            self.highlightMatchedProcs()
        elif btnName == 'ShowProcsWithSim':
            c = VBFunctionChooser("Procedures with Matches", False, self.matchedProcsCache)
            c.Show()
        elif btnName == 'ShowMatchedProcs':
            if self.ui.listProcsWithSim.currentItem() is not None:
                rvaStr = self.ui.listProcsWithSim.currentItem().text()
                self.openMatchedProcsChooser(rvaStr)
            else:
                self.notifyStatus({
                    'statuscode': 1,
                    'message': 'No procedure has been selected'
                })
        elif btnName == 'MatchedLeftProcMoreInfo' or btnName == 'MatchedRightProcMoreInfo':
            print 'NOT IMPLEMENTED: IT WILL SHOW JUICE INFO IN A NEW IDA VIEW, GRAPHS, ...'
        elif btnName == 'ShowChild':
            print 'NOT IMPLEMENTED: IT WILL SHOW Strings, dots, json related to the child...'
        else:
            self.status('idle', 'black')

    def openMatchedProcsChooser(self, rvaStr):
            rva = int(rvaStr, 16)
            c = VBFunctionChooser(
                    'Address %s matched procedures' % hex(VBIDAHelper.addressFromRVA(rva)), 
                    True,
                    self.matchedProcsCache,
                    self.openedFileHash + '/' + rvaStr,
                    rva
                )
            c.Show()

    def listProfileItemChanged(self, item):
        self.ui.btnRemoveProfile.setEnabled(True)
        self.loadProfile()

    def listProcsWithSimItemChanged(self, item):
        if item is not None:
            rva = item.text()
            self.clearMatchedProcedureRight()
            disassemblyInfo = self.juiciesCache.read(self.openedFileHash)[rva]
            if 'binary_id' in disassemblyInfo:
                self.ui.editMatchedLeftBinID.setText(disassemblyInfo['binary_id'])
            if 'startRVA' in disassemblyInfo:
                self.ui.editMatchedLeftProcRVA.setText(disassemblyInfo['startRVA'])
            if 'procName' in disassemblyInfo:
                self.ui.editMatchedLeftProcName.setText(disassemblyInfo['procName'])
            if 'peSegment' in disassemblyInfo:
                self.ui.editMatchedLeftProcSegment.setText(disassemblyInfo['peSegment'])
            if 'code_size' in disassemblyInfo:
                self.ui.editMatchedLeftProcCodeSize.setText(str(disassemblyInfo['code_size']))
            if 'semantics_size' in disassemblyInfo:
                self.ui.editMatchedLeftProcSemSize.setText(str(disassemblyInfo['semantics_size']))
            if 'isThunk' in disassemblyInfo:
                if disassemblyInfo['isThunk']:
                    self.ui.checkMatchedLeftProcIsThunk.setCheckState(QtCore.Qt.CheckState.Checked)
                else:
                    self.ui.checkMatchedLeftProcIsThunk.setCheckState(QtCore.Qt.CheckState.Unchecked)
            if 'isLibrary' in disassemblyInfo:
                if disassemblyInfo['isLibrary']:
                    self.ui.checkMatchedLeftProcIsLib.setCheckState(QtCore.Qt.CheckState.Checked)
                else:
                    self.ui.checkMatchedLeftProcIsLib.setCheckState(QtCore.Qt.CheckState.Unchecked)

            self.ui.listMatchedProcs.clear()
            matchedProcs = self.matchedProcsCache.read(self.openedFileHash+'/'+rva)
            for mProc in  matchedProcs:
                self.ui.listMatchedProcs.addItem(mProc['proc_id'])
    
    # def editMatchedLeftProcRVATextChanged(self):
    #     if self.ui.editMatchedLeftProcRVA.text() != '':
    #         if self.ui.editMatchedRightProcRVA.text() != '':
    #             self.ui.btnDiffProcs.setEnabled(True)
    #         else:
    #             self.ui.btnDiffProcs.setEnabled(False)
    #         self.ui.btnMatchedLeftProcMoreInfo.setEnabled(True)
    #     else:
    #         self.ui.btnMatchedLeftProcMoreInfo.setEnabled(False)
    #         self.ui.btnDiffProcs.setEnabled(False)

    # def editMatchedRightProcRVATextChanged(self):
    #     if self.ui.editMatchedRightProcRVA.text() != '':
    #         if self.ui.editMatchedLeftProcRVA.text() != '':
    #             self.ui.btnDiffProcs.setEnabled(True)
    #         else:
    #             self.ui.btnDiffProcs.setEnabled(False)

    #         self.ui.btnMatchedRightProcMoreInfo.setEnabled(True)
    #     else:
    #         self.ui.btnMatchedRightProcMoreInfo.setEnabled(False)
    #         self.ui.btnDiffProcs.setEnabled(False)

    def listMatchedProcsItemChanged(self, item):
        if item is not None:
            binHash, rva = item.text().split('/')
            matchedProcInfo = self.juiceIndividualCache.read(item.text())
            if matchedProcInfo is None:
                self.showProc(binHash, rva)
            else:
                self.loadMatchedProcedure(matchedProcInfo)

    def clearBinaryForm(self):
        self.ui.editSHA.clear()
        self.ui.editFileType.clear()
        self.ui.editFileLength.clear()
        self.ui.editOrigFilePath.clear()
        self.ui.editUploadedDate.clear()
        self.ui.editClassObject.clear()
        self.ui.editMD5.clear()
        self.ui.listChildren.clear()
        self.ui.btnDownloadBinary.setEnabled(False)
        self.ui.btnRefreshBinary.setEnabled(False)

    def loadListBinaries(self, binaries):
        self.clearBinaryForm()
        self.clearChildForm()
        self.ui.listBins.clear()
        for bin in binaries:
            self.ui.listBins.addItem(bin['_id'])

    def checkOpenedFile(self, binaries):
        for bin in binaries:
            if bin['_id'] == self.openedFileHash:
                return True
        return False

    def uploadFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        self.queryAll()

    def upload(self, path):
        if self.checkAPIKey():
            cmd = VBAsyncCommand('upload', self.APIKey, path, path)
            cmd.finishedProcessing.connect(self.uploadFinished)
            self.waitCursor(True)
            self.status('Uploading opened file...', 'black')
            cmd.start()

    def listMatchedBinsItemChanged(self, item):
        if item is not None:
            matchedBins = self.matchedBinsCache.read('matches')
            for binary in matchedBins:
                if binary['_id'] == item.text():
                    if 'similarity' in binary:
                        self.ui.lcdSimilarity.display(binary['similarity'])
                    if 'fileHash' in binary:
                        self.ui.editMatchedBinSHA.setText(binary['fileHash'])
                    self.ui.btnDownloadMatchedBin.setEnabled(True)

    def clearMatchedBinForm(self):
        self.ui.lcdSimilarity.display(0)        
        self.ui.editMatchedBinSHA.clear()
        self.ui.btnDownloadMatchedBin.setEnabled(False)

    def loadListMatchedBinaries(self, matches):
        self.clearMatchedBinForm()
        self.ui.listMatchedBins.clear()
        for match in matches:
            self.ui.listMatchedBins.addItem(match['_id'])
        juice = self.juiciesCache.read(self.openedFileHash)
        if juice is None:            
            self.showBinary(self.openedFileHash)
        else:
            self.searchProcs(juice)

    def MatchedBinariesUpdated(self, matches):        
        self.loadListMatchedBinaries(matches)

    def loadListProcs(self):
        self.ui.listProcsWithSim.clear()      
        matchedProcs = self.matchedProcsCache.readAll()
        self.ui.lcdMatchedProcs.display(len(matchedProcs))
        for proc in matchedProcs:
            self.ui.listProcsWithSim.addItem(proc.split('/')[1])
        self.ui.listProcsWithSim.sortItems()

    def MatchedProcsUpdated(self, procs):
        self.loadListProcs()

    def searchBinariesFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if result['statuscode'] == 0:
            if 'matches' in result['answer']:
                self.matchedBinsCache.update('matches', result['answer']['matches'])

    def searchBinaries(self, hash):
        if self.checkAPIKey():
            threshold = self.ui.boxThreshold.value()
            upperhalf = True if self.ui.checkUpperHalf == QtCore.Qt.CheckState.Checked else False
            cmd = VBAsyncCommand('searchBins', self.APIKey, hash, threshold, upperhalf)
            cmd.finishedProcessing.connect(self.searchBinariesFinished)
            self.waitCursor(True)
            self.status('Searching similar binaries...', 'black')
            cmd.start()

    def queryAllFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if result['statuscode'] == 0:
            binaries = result['answer']
            self.binaryListCache.update('binaries', binaries)
            if self.checkOpenedFile(binaries):
                self.notifyStatus({
                    'statuscode': 0,
                    'message': 'File is already uploaded'
                })
            elif self.openedFilePath == '':
                self.notifyStatus({
                    'statuscode': 1,
                    'message': 'Opened file could not be found'
                })
                return
            else:
                self.upload(self.openedFilePath)

    def checkAPIKey(self):
        if self.APIKey == '' or self.APIKey is None:
            self.notifyStatus({
                'statuscode': 1,
                'message': 'API Key is not set. Go to the configuration tab and set your API key'
            })
            return False
        return True

    def queryAll(self):
        if self.checkAPIKey():
            cmd = VBAsyncCommand('query', self.APIKey)
            cmd.finishedProcessing.connect(self.queryAllFinished)
            self.waitCursor(True)
            self.status('Loading all uploaded binaries...', 'black')
            cmd.start()

    def clearChildForm(self):
        self.ui.editChildUnpackerMessage.clear()
        self.ui.editChildUnpackerTime.clear()
        self.ui.editChildHash.clear()
        self.ui.editChildStatus.clear()
        self.ui.editChildServiceName.clear()
        self.ui.btnDownloadChildBinary.setEnabled(False)

    def fillBinaryInfoForm(self, result):
        self.clearChildForm()
        self.ui.btnDownloadBinary.setEnabled(True)
        self.ui.btnRefreshBinary.setEnabled(True)
        if 'sha1' in result:
            self.ui.editSHA.setText(result['sha1'])
        if 'unix_filetype' in result:
            self.ui.editFileType.setText(result['unix_filetype'])
        if 'length' in result:
            self.ui.editFileLength.setText(str(result['length']) + ' bytes')
        if 'uploadDate' in result:
            self.ui.editUploadedDate.setText(result['uploadDate'][:19])
        if 'object_class' in result:
            self.ui.editClassObject.setText(result['object_class'])
        if 'md5' in result:
            self.ui.editMD5.setText(result['md5'])
        if 'origFilepath' in result and len(result['origFilepath']) > 0:
            self.ui.editOrigFilePath.setText(result['origFilepath'][0])
        self.ui.listChildren.clear()
        if 'children' in result:
            for child in result['children']:
                self.ui.listChildren.addItem(child['child'])

    def binaryInfoUpdated(self, binaryInfo):
        self.fillBinaryInfoForm(binaryInfo)

    def queryFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if result['statuscode'] == 0:
            self.binaryInfoCache.update(
                result['hash'], result['answer']
            )

    def query(self, hash):
        if self.checkAPIKey():
            cmd = VBAsyncCommand('query', self.APIKey, hash)
            cmd.finishedProcessing.connect(self.queryFinished)
            self.waitCursor(True)
            self.status('Loading binary information for hash %s...' % hash, 'black')
            cmd.start()

    def reprocessFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if result['statuscode'] == 0:
            self.query(result['hash'])

    def reprocess(self, hash):
        if self.checkAPIKey():
            cmd = VBAsyncCommand('reprocess', self.APIKey, hash)
            cmd.finishedProcessing.connect(self.reprocessFinished)
            self.waitCursor(True)
            self.status('Re-processing binary for hash %s...' % hash, 'black')
            cmd.start()

    def searchProcedureFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if self.rvaProcessing is None:
            return
        processingId = self.openedFileHash+'/'+self.rvaProcessing

        if result['statuscode'] == 0:
            answer = result['answer']
            simEqList = []           
            
            for similar in answer['similar_procedures']:
                for s in similar:                    
                    s.update({'_similar': True})
                    simEqList.append(s)

            for equivalent in answer['semantically_equivalent_procedures']:                
                if processingId != equivalent['proc_id']:                    
                    equivalent.update({'_equal': True})                                
                    simEqList.append(equivalent)

            if len(simEqList) > 0:
                self.matchedProcsCache.update(processingId, simEqList)
        
        self.searchAvailableProcedureInList()

    def searchAvailableProcedureInList(self):
        if self.checkAPIKey() and len(self.rvaProcessingList) > 0:
            noLibProc = False
            if self.ui.checkNoLibProc.checkState() == QtCore.Qt.CheckState.Checked:
                noLibProc = True
            self.rvaProcessing = self.rvaProcessingList.pop()
            if self.rvaProcessing is not None:
                cmd = VBAsyncCommand('searchProcs', self.APIKey, self.openedFileHash, 
                    self.rvaProcessing, noLibProc)
                cmd.finishedProcessing.connect(self.searchProcedureFinished)
                self.waitCursor(True)
                self.status('Searching for procedure at rva %s...' % self.rvaProcessing, 'black')
                cmd.start()   

    def searchProcs(self, result):
        self.rvaProcessing = None
        self.rvaProcessingList = []        
        for k in result:
            self.rvaProcessingList.append(k)
        if len(self.matchedProcsCache.readAll()) > 0:
            self.loadListProcs()
        else:
            self.searchAvailableProcedureInList()

    def showProc(self, hash, rva):
        if self.checkAPIKey():
            noLibProc = False
            if self.ui.checkNoLibProc.checkState() == QtCore.Qt.CheckState.Checked:
                noLibProc = True
            cmd = VBAsyncCommand('showProc', self.APIKey, hash, rva, noLibProc)
            cmd.finishedProcessing.connect(self.showProcFinished)
            self.waitCursor(True)
            self.status('Retrieving disassembly for procedure of binary %s at rva %s...' % 
                (hash, rva), 'black')
            cmd.start()

    def showProcFinished(self, result):
        self.notifyStatus(result)
        self.waitCursor(False)
        if result['statuscode'] == 0:
            answer = result['answer']            
            self.juiceIndividualCache.update(answer['_id'], answer)

    def juiceUpdated(self, result):        
            self.searchProcs(result)

    def clearMatchedProcedureRight(self):
        self.ui.editMatchedRightBinID.clear()
        self.ui.editMatchedRightProcRVA.clear()
        self.ui.editMatchedRightProcName.clear()
        self.ui.editMatchedRightProcSegment.clear()
        self.ui.editMatchedRightProcCodeSize.clear()
        self.ui.editMatchedRightProcSemSize.clear()
        self.ui.checkMatchedRightProcIsThunk.setCheckState(QtCore.Qt.CheckState.Unchecked)
        self.ui.checkMatchedRightProcIsLib.setCheckState(QtCore.Qt.CheckState.Unchecked)

    def loadMatchedProcedure(self, result):
        if 'binary_id' in result:
            self.ui.editMatchedRightBinID.setText(result['binary_id'])
        if 'startRVA' in result:
            self.ui.editMatchedRightProcRVA.setText(result['startRVA'])
        if 'procName' in result:
            self.ui.editMatchedRightProcName.setText(result['procName'])
        if 'peSegment' in result:
            self.ui.editMatchedRightProcSegment.setText(result['peSegment'])
        if 'code_size' in result:
            self.ui.editMatchedRightProcCodeSize.setText(str(result['code_size']))
        if 'semantics_size' in result:
            self.ui.editMatchedRightProcSemSize.setText(str(result['semantics_size']))
        if 'isThunk' in result:
            if result['isThunk']:
                self.ui.checkMatchedRightProcIsThunk.setCheckState(QtCore.Qt.CheckState.Checked)
            else:
                self.ui.checkMatchedRightProcIsThunk.setCheckState(QtCore.Qt.CheckState.Unchecked)
        if 'isLibrary' in result:
            if result['isLibrary']:
                self.ui.checkMatchedRightProcIsLib.setCheckState(QtCore.Qt.CheckState.Checked)
            else:
                self.ui.checkMatchedRightProcIsLib.setCheckState(QtCore.Qt.CheckState.Unchecked)

    def juiceIndividualUpdated(self, result):
        self.loadMatchedProcedure(result)

    def showBinaryFinished(self, result):
        """Retrieving disassembly information finished
        
        Args:
            result (Str): result from the server        
        """
        self.notifyStatus(result)
        self.waitCursor(False)
        self.juiciesCache.update(self.openedFileHash, result['answer'])        

    def showBinary(self, hash):
        if self.checkAPIKey():
            noLibProc = False
            if self.ui.checkNoLibProc.checkState() == QtCore.Qt.CheckState.Checked:
                noLibProc = True
            cmd = VBAsyncCommand('showBin', self.APIKey, hash, noLibProc)
            cmd.finishedProcessing.connect(self.showBinaryFinished)
            self.waitCursor(True)
            self.status('Retrieving binary disassembly for hash %s...' % hash, 'black')
            cmd.start()

    def binaryListUpdated(self, binaries):
        self.loadListBinaries(binaries)

    def abortSearchingProcedures(self):
        self.rvaProcessing = None
        self.rvaProcessingList = []

    def loadBinaryTab(self):
        self.abortSearchingProcedures()
        bins = self.binaryListCache.read('binaries')
        if bins is None:
            self.queryAll()
        else:
            self.loadListBinaries(bins)

    def loadMatchedTab(self):
        if self.openedFileHash == '':
            self.notifyStatus({
                'statuscode': 1,
                'message': 'Opened file could not be found'
            })
            return
        
        matches = self.matchedBinsCache.read('matches')
        if matches is None:
            self.searchBinaries(self.openedFileHash)
        else:
            self.loadListMatchedBinaries(matches)

    def reloadSimilarBinsClicked(self):
        if self.openedFileHash == '':
            self.notifyStatus({
                'statuscode': 1,
                'message': 'Opened file could not be found'
            })
            return

        self.searchBinaries(self.openedFileHash)

    def ReloadMatchedProcsClicked(self):
        self.rvaProcessing = None
        self.rvaProcessingList = []        
        juice = self.juiciesCache.read(self.openedFileHash)
        if juice is not None:
            for k in juice:
                self.rvaProcessingList.append(k)
            
            self.searchAvailableProcedureInList() 

    def tabWidgetVBChanged(self, index):
        if index == 0:
            self.loadBinaryTab()
        if index == 1:
            self.loadMatchedTab()

    def toolBoxCurrentChanged(self, index):        
        if index == 1:
            tabIndex = self.ui.tabWidgetVB.currentIndex()
            self.tabWidgetVBChanged(tabIndex)
        else: 
            self.abortSearchingProcedures()

    def listBinsItemChanged(self, item):
        if item is not None:
            result = self.binaryInfoCache.read(item.text())
            if result is not None:
                self.fillBinaryInfoForm(result)
            else:
                self.query(item.text())

    def listChildrenItemChanged(self, item):
        if item is not None and self.ui.listBins.currentItem() is not None:
            children = self.binaryInfoCache.read(self.ui.listBins.currentItem().text())['children']
            for child in children:
                if child['child'] == item.text():
                    break
            if type(child) is dict:
                self.ui.btnDownloadChildBinary.setEnabled(True)
                self.ui.editChildHash.setText(child['child'])
                if 'status' in child:
                    self.ui.editChildStatus.setText(child['status'])
                if 'service_name' in child:
                    serviceName = child['service_name']
                    if serviceName == 'srlStatic':
                        serviceName = "%s, %s"%(serviceName, child['service_data']['analysis_name'])
                    self.ui.editChildServiceName.setText(serviceName)
                if 'service_data' in child:
                    serviceData = child['service_data']
                    if 'unpacker_result' in serviceData:
                        self.ui.editChildUnpackerTime.setText(serviceData['unpacker_result']['time'])
                        self.ui.editChildUnpackerMessage.setText(serviceData['unpacker_result']['message'])

    def downloadFinished(self, path):
        self.notifyStatus({
            'statuscode': 0,
            'message': 'File downloaded to %s successfully' % path
        })
        self.waitCursor(False)

    def download(self, hash, isChild):
        typeExtension = {
            'archive.zip': 'zip',            
            'binary.pe32': 'exe',
            'srlJuice': 'juice.json',
            'srlUnpacker': 'unp.exe',
            'srlStatic, srlAPIForwardFlowGraph': 'apiflowgraph.json',
            'srlStatic, srlStrings': 'strings.json',
            'srlStatic, srlCallgraph': 'callgraph.dot',
        }
        if self.checkAPIKey():
            downloadFolder = self.currentDir + os.sep + 'download'
            if not os.path.isdir(downloadFolder):
                os.mkdir(downloadFolder)

            if isChild:
                fileType = self.ui.editChildServiceName.text()                 
            else:
                fileType = self.ui.editClassObject.toPlainText()

            try:
                extension = typeExtension[fileType]
            except:
                extension = 'bin'

            cmd = VBAsyncCommand('download', self.APIKey, hash, '%s%sdownload%s%s.%s' %
                (self.currentDir, os.sep, os.sep, hash, extension))
            cmd.finishedProcessing.connect(self.downloadFinished)
            self.waitCursor(True)
            self.status('Downloading file for hash %s...' % hash, 'black')
            cmd.start()

    def highlightMatchedProcs(self):
        matchedProcs = self.matchedProcsCache.readAll()
        prefix = '[%s]\n[!] Matched Procedures: \n' % self.ui.editHighlightCaption.toPlainText()        
        if len(matchedProcs) > 0:
            for proc in matchedProcs:
                procStr = ''
                rva = proc.split('/')[1]
                ea = VBIDAHelper.addressFromRVA(int(rva, 16))
                matched = self.matchedProcsCache.read(proc)
                for m in matched:
                    mbinary, mrva = m['proc_id'].split('/')
                    procStr += 'Procedure: %s, Binary: %s, RVA: %s\n'%(
                        m['procName'], mbinary, mrva)

                cmt =  prefix + procStr
                cmt = cmt.encode('ascii','ignore')
                
                VBIDAHelper.setFunctionComment(ea, cmt)

                css = self.ui.btnHighlightColorChooser.styleSheet()
                start = css.find('rgb')
                if start != -1:
                    start += 4
                    end = css.find(')')
                    t = css[start : end]
                    rgb = map(str, t.split(','))
                    rgb = map(str.strip, rgb)
                    rgb = map(int, rgb)
                    VBIDAHelper.setFunctionColor(ea, rgb[2], rgb[1], rgb[0])

            self.notifyStatus({
                'statuscode': 0,
                'message': '%s procedures has been highlighted'%len(matchedProcs)
            })