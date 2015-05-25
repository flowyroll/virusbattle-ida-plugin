"""Profile management

"""
import json
import os

class VBProfile(object):
    """Profile management class
    
    Returns:
        TYPE: Description
    """
    def __init__(self, name=None, key=None, hCaption=None, hColor=None, 
        threshold=None, upperHalf=None, noLibProc=None, serverPort=None):
        """Constructor for VBProfile
        
        Returns:
            TYPE: Description
        """
        self.setConfig(name, key, hCaption, hColor, threshold, upperHalf, noLibProc, serverPort)
        try:
            self.configPath = os.environ['USERPROFILE'] + os.sep + '.VirusBattle'
        except:
            self.configPath = os.environ['$HOME'] + os.sep + '.VirusBattle'

    def setConfig(self, name, key, hCaption, hColor, threshold, upperHalf, noLibProc, serverPort=80):
        """Set configuration parameters
        
        Args:
            name (Str): Profile name
            key (Str): API Key
            hCaption (Str): Highlight Caption
            hColor (Str): Highlight Color
            threshold (Str): Description
            upperHalf (Str): Description
            noLibProc (Str): Description
        
        Returns:
            TYPE: Description
        """
        self.config = {
            'Name': name,
            'APIKey': key,
            'HighlightCaption': hCaption,
            'HighlightColor': hColor,
            'Threshold': threshold,
            'Upperhalf': upperHalf,
            'NoLibProc': noLibProc,
            'serverPort': serverPort
        }

    def readConfig(self):
        """Read config file
        
        Returns:
            TYPE: Description
        """
        f = open(self.configPath, 'r')
        result = f.read()
        f.close()
        return result

    def writeConfig(self, config):
        """Write config to configuration file
        
        Args:
            config (Str): configuration data
        
        Returns:
            TYPE: Description
        """
        f = open(self.configPath, 'w+')
        f.write(config)
        f.close()

    def save(self):
        """Save current configuration in this object to the file
        
        Returns:
            TYPE: Description
        """
        if os.path.exists(self.configPath):
            configs = json.loads(self.readConfig())
            isExist = False
            for i in xrange(len(configs)):
                if configs[i]['Name'] == self.config['Name']:
                    configs[i] = self.config
                    isExist = True

            if not isExist:
                configs.append(self.config)
        else:
            configs = [self.config]

        self.writeConfig(json.dumps(configs))
        return {
            'statuscode': 0,
            'message': 'Profile saved successfully'
        }

    def remove(self):
        """remove this configuration from the file
        
        Returns:
            TYPE: Description
        """
        if os.path.exists(self.configPath):
            configs = json.loads(self.readConfig())
            for config in configs:
                if config['Name'] == self.config['Name']:
                    configs.remove(config)
                    self.writeConfig(json.dumps(configs))
                    return {
                        'statuscode': 0,
                        'message': 'Profile removed successfully'
                    }
        return {
            'statuscode': 1,
            'message': 'Profile does not exist'
        }

    @staticmethod
    def load(name):
        """Load a specific profile configuration
        
        Args:
            name (Str): Name of the profile
        
        Returns:
            TYPE: Dict
        """
        profile = VBProfile()
        if os.path.exists(profile.configPath):
            configs = json.loads(profile.readConfig())
            for config in configs:
                if config['Name'] == name:
                    profile.setConfig(
                        config['Name'],
                        config['APIKey'],
                        config['HighlightCaption'],
                        config['HighlightColor'],
                        config['Threshold'],
                        config['Upperhalf'],
                        config['NoLibProc'],
                        config['serverPort']
                    )
                    return profile

        return {
            'statuscode': 1,
            'message': 'Profile does not exist'
        }

    @staticmethod
    def loadAll():
        """Load all available profiles
        
        Returns:
            TYPE: List
        """
        profiles = []
        profile = VBProfile()
        if os.path.exists(profile.configPath):
            configs = json.loads(profile.readConfig())
            for config in configs:
                profiles.append(
                    VBProfile(
                        config['Name'],
                        config['APIKey'],
                        config['HighlightCaption'],
                        config['HighlightColor'],
                        config['Threshold'],
                        config['Upperhalf'],
                        config['NoLibProc'],
                        config['serverPort']
                    )
                )
        return profiles