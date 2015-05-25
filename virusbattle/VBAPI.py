"""Virusbattle REST Web Service API Client

"""
import requests

API_BASE_URL = 'http://api.virusbattle.com/'

class VBAPI(object): 
    """Virusbattle REST Web Service API Client Class
    Check http://api.virusbattle.com/docs for complete documentation
    """
    @staticmethod
    def register(email, name):
        """Register a new Virusbattle user, API Key will be sent to the email
        on approve
        
        Args:
            email (Str): Valid Email Address
            name (Str): Username
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['register'],
            {
                'email': email,
                'name': name
            }
        )

    @staticmethod
    def url(sections):
        """Make up the complete route to the service
        
        Args:
            sections (List): List of route section
        
        Returns:
            TYPE: String
        """
        return API_BASE_URL + '/'.join(sections)

    @staticmethod
    def get(sections, params, download=False, stream=False):
        """Wrapper around requests.get that return JSON or binary dependent on
        the download parameter
        
        Args:
            sections (List): List of route sections
            params (Dict): URL parameters
            download (bool, optional): Is Download request?
            stream (bool, optional): stream of downloading bytes
        
        Returns:
            TYPE: Dict 
        """
        r = requests.get(VBAPI.url(sections), params=params, stream=stream)
        print r.url
        if not download:
            return r.json()
        return r

    @staticmethod
    def download(APIKey, fileHash, path, zipBinary=False):
        """Download an object
        
        Args:
            APIKey (Str): API Key
            fileHash (Str): SHA hash of the object
            path (Str): The path to save downloaded content
            zipBinary (bool, optional): Download the file in compressed format
        
        Returns:
            TYPE: Str
        """
        r = VBAPI.get(
            ['download', APIKey, fileHash],
            {
                'zipBinary': 1 if zipBinary else 0
            },
            True,
            True
        )

        with open(path, 'wb') as fd:
            for chunk in r.__iter__():
                if chunk:
                    fd.write(chunk)
                    fd.flush()
        return path


    @staticmethod
    def query(APIKey, fileHash=''):
        """Query for all uploaded binaries or a specific binary based on the 
        fileHash
        
        Args:
            APIKey (Str): API Key
            fileHash (str, optional): SHA hash of the file
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['query', APIKey, fileHash],
            {}
        )

    @staticmethod
    def searchProcs(APIKey, binaryID, rva=None, noLibProc=False):
        """Search all procedures or a specific procedure in a binary for 
        similar/equal procs
        
        Args:
            APIKey (Str): API Key
            binaryID (Str): SHA hash of the binary
            rva (Str, optional): Relative address of a specific procedure
            noLibProc (bool, optional): Exclude Library procedures
        
        Returns:
            TYPE: Dict
        """
        rva_str = str(rva) if rva is not None else ''
        return VBAPI.get(
            ['search', 'procs', APIKey, binaryID, rva_str],
            {
                'noLibProc': noLibProc
            }
        )

    @staticmethod
    def searchBins(APIKey, binaryID, threshold=0.7, upperhalf=False):
        """Search all uploaded binaries for similar binaries
        
        Args:
            APIKey (Str): API Key
            binaryID (Str): SHA hash of the binary
            threshold (float, optional): Description
            upperhalf (bool, optional): Description
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['search', 'binary', APIKey, binaryID],
            {
                'threshold': threshold,
                'upperhalf': 1 if upperhalf else 0
            }
        )

    @staticmethod
    def showProc(APIKey, binaryID, rva, noLibProc=False):
        """Show disassembly information of a specific procedure using Juice
        service
        
        Args:
            APIKey (Str): API Key
            binaryID (Str): SHA hash of the binary
            rva (Str): Relative address of a specific procedure
            noLibProc (bool, optional): Exclude Library procedures
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['show', 'proc', APIKey, binaryID, str(rva)],
            {
                'noLibProc': noLibProc
            }
        )

    @staticmethod
    def showBin(APIKey, binaryID, noLibProc=False):
        """Show disassembly information of a binary using Juice
        
        Args:
            APIKey (Str): API Key
            binaryID (Str): SHA hash of teh binary
            noLibProc (bool, optional): Exclude Library procedures
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['show', 'binary', APIKey, binaryID],
            {
                'noLibProc': noLibProc
            }
        )

    @staticmethod
    def upload(APIKey, path, origFilepath='', password='', unpackerConfig=''):
        """Upload a new sample to Virusbattle service
        
        Args:
            APIKey (Str): APIKey
            path (Str): Path of the file to be uploaded
            origFilepath (str, optional): File path that will be saved on the server
            password (str, optional): Password if it is a compressed protected file
            unpackerConfig (str, optional): Description
        
        Returns:
            TYPE: Dict
        """
        files = {'filedata': open(path, 'rb')}
        url = VBAPI.url(['upload', APIKey])
        r = requests.post(
            url,
            files=files,
            params={
                'origFilepath': origFilepath,
                'password': password,
                'unpackerConfig': unpackerConfig
            }
        )
        return r.json()

    @staticmethod
    def reprocess(APIKey, binaryID, force_sim=True):
        """Reprocess a previously uploaded sample
        
        Args:
            APIKey (Str): API Key
            binaryID (Str): SHA hash of the binary
            force_sim (bool, optional): Force to run similarity check service
        
        Returns:
            TYPE: Dict
        """
        return VBAPI.get(
            ['reprocess', APIKey, binaryID],
            {
                'force_sim': 1 if force_sim else 0
            }
        )

    @staticmethod
    def avscans(APIKey, fileHash):
        return VBAPI.get(
            ['other/avscans', APIKey, fileHash],
            {}
        )

    @staticmethod
    def behaviors(APIKey, fileHash):
        return VBAPI.get(
            ['other/behaviors', APIKey, fileHash],
            {}
        )

    @staticmethod
    def pedata(APIKey, fileHash):
        return VBAPI.get(
            ['other/pedata', APIKey, fileHash],
            {}
        )