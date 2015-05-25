import os
from string import Template

class VBTemplateHelper(object):
    @staticmethod
    def loadTemplate(name):
        try:
            currentDir = os.path.abspath(
                os.path.join(os.path.realpath(__file__), os.pardir)
            )
            f = open('%s%s%s.htm'%
                (currentDir, os.sep, name),
                'r'
            )
            data = f.read()
            f.close()
            return data
        except:
            return None

    @staticmethod
    def buildAVScansPage(answer):
        template = VBTemplateHelper.loadTemplate('avscans')
        if template is not None:
            offsetEndOfHeader = template.find('<!-- REPEAT -->')
            endRepeat = '<!-- END REPEAT -->'
            offsetStartOfFooter = template.find(endRepeat) + len(endRepeat) 
            headerTmpl = template[0:offsetEndOfHeader]
            repeatTmpl = template[offsetEndOfHeader:offsetStartOfFooter]
            footerTmpl = template[offsetStartOfFooter: len(template) -1]
            sha1 = ''
            if 'sha1' in answer:
                sha1 = answer['sha1']
            size = 0
            if 'size' in answer:
                size = answer['size']
            positives = 0
            if 'positives' in answer:
                positives = answer['positives']
            total = 0
            if 'total' in answer:
                total = answer['total']
            firstSeen = ''
            if 'first_seen' in answer:
                firstSeen = answer['first_seen']
            scanDate = ''
            if 'scan_date' in answer:
                scanDate = answer['scan_date']

            header = Template(headerTmpl).substitute(
                sha1=sha1, size=size, positives=positives, total=total, 
                firstSeen=firstSeen, scanDate=scanDate
            )

            body = ''
            if 'scans' in answer:
                scans = answer['scans']
                for scan in scans:
                    bodyPart = Template(repeatTmpl).substitute(
                        detected=scan['detected'], 
                        version=scan['version'],
                        update=scan['update'],
                        name=scan['name'],
                        scanner=scan['scanner']
                    )
                    body += bodyPart

            footer = footerTmpl
            return header+body+footer
        else:
            return None