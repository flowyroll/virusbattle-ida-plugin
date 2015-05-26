"""Main entrypoint for the plugin that make an instance of the MainWidget and 
set it to IDA layout

Returns:
    TYPE: Description
"""
from idaapi import PluginForm
from PySide import QtCore, QtGui
from virusbattle.VBMainWidget import VBMainWidget
import virusbattle.VBIDAHelper

class VBPluginForm(PluginForm):
    """IDA Plugin Form 
        
    """
    def OnCreate(self, form):
        """Make an instance of `VBMainWidget` and set it in the form layout
        on create
        
        Args:
            form (TYPE): Description
        
        """
        self.parent = self.FormToPySideWidget(form)
        layout = QtGui.QVBoxLayout()
        self.widget = VBMainWidget()
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)       

    def OnClose(self, form):
        """
        
        Args:
            form (TYPE): Description                
        """

def main():
    """Run the Plugin form
        
    """
    plg = VBPluginForm()
    plg.Show('Virus Battle', PluginForm.FORM_SAVE | PluginForm.FORM_RESTORE )

if __name__ == "__main__":
    main()