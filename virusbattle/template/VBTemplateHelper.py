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
    def buildPEDataPage(answer):
        template = VBTemplateHelper.loadTemplate('pedata')
        if template is not None:
            offset1 = template.find('<!-- Lang Codes -->')
            headerTmpl = template[0:offset1]
            t = '<!-- End Lang Codes -->'
            offset2 = template.find(t) + len(t)
            resourceLangTmpl = template[offset1:offset2]
            
            offset1 = template.find('<!-- Imports -->')
            body1Tmpl = template[offset2:offset1]
            t = '<!-- End Imports -->'
            offset2 = template.find(t) + len(t)
            importsTmpl = template[offset1:offset2]

            offset1 = template.find('<!-- Resource Types -->')
            body2Tmpl = template[offset2:offset1]
            t = '<!-- End Resource Types -->'
            offset2 = template.find(t) + len(t)
            resourceTypesTmpl = template[offset1:offset2]

            offset1 = template.find('<!-- Sections -->')
            body3Tmpl = template[offset2:offset1]
            t = '<!-- End Sections -->'
            offset2 = template.find(t) + len(t)
            sectionsTmpl = template[offset1:offset2]

            footerTmpl = template[offset2:len(template)]

            pe = answer['pe_data']

            header = Template(headerTmpl).substitute(
                magic=pe['magic'], 
                publisher=pe['sigcheck']['publisher'], 
                product=pe['sigcheck']['product'], 
                verified=pe['sigcheck']['verified'], 
                internalName=pe['sigcheck']['internal name'], 
                copyright=pe['sigcheck']['copyright'],
                originalName=pe['sigcheck']['internal name'],
                fileVersion=pe['sigcheck']['file version'],
                description=pe['sigcheck']['description'],

                subsystemVersion=pe['exiftool']['SubsystemVersion'],
                linkerVersion=pe['exiftool']['LinkerVersion'],
                imageVersion=pe['exiftool']['ImageVersion'],
                fileSubtype=pe['exiftool']['FileSubtype'],
                fileVersionNumber=pe['exiftool']['FileVersionNumber'],
                uninitDataSize=pe['exiftool']['UninitializedDataSize'],
                langCode=pe['exiftool']['LanguageCode'],
                fileFlagsMask=pe['exiftool']['FileFlagsMask'],
                charSet=pe['exiftool']['CharacterSet'],
                initDataSize=pe['exiftool']['InitializedDataSize'],
                fileOS=pe['exiftool']['FileOS'],
                mimeType=pe['exiftool']['MIMEType'],
                legalCopyright=pe['exiftool']['LegalCopyright'],
                fileVersion2=pe['exiftool']['FileVersion'],
                timeStamp=pe['exiftool']['TimeStamp'],
                fileType=pe['exiftool']['FileType'],
                peType=pe['exiftool']['PEType'],
                internalName2=pe['exiftool']['InternalName'],
                productVersion=pe['exiftool']['ProductVersion'],
                fileDescription=pe['exiftool']['FileDescription'],
                OSVersion=pe['exiftool']['OSVersion'],
                origFileName=pe['exiftool']['OriginalFilename'],
                subsystem=pe['exiftool']['Subsystem'],
                machineType=pe['exiftool']['MachineType'],
                companyName=pe['exiftool']['CompanyName'],
                codeSize=pe['exiftool']['CodeSize'],
                productName=pe['exiftool']['ProductName'],
                productVerNumber=pe['exiftool']['ProductVersionNumber'],
                entryPoint=pe['exiftool']['EntryPoint'],
                objectFileType=pe['exiftool']['ObjectFileType'],

                trid=pe['trid'],
            )

            langTypes = ''
            langs = pe['pe-resource-langs']
            for k in langs:
                l = Template(resourceLangTmpl).substitute(
                    langCaption=k,
                    langCode2=langs[k],
                )
                langTypes += l

            body1 = Template(body1Tmpl).substitute(peTimestamp=pe['pe-timestamp'])


            imports = ''
            imps = pe['imports']
            for imp in imps:
                i = Template(importsTmpl).substitute(
                    DLLName=imp['dllname'],
                    procs=str(imp['procs']),
                )
                imports += i

            body2 = Template(body2Tmpl).substitute(
                peEntryPoint=pe['pe-entry-point']
            )

            resTypes = pe['pe-resource-types']
            resourceTypes = ''
            for k in resTypes:
                r = Template(resourceTypesTmpl).substitute(
                    resourceName=k,
                    resourceNumber=resTypes[k],
                )
                resourceTypes += r

            body3 = body3Tmpl

            sects = pe['sections']
            sections = ''
            for sect in sects:
                s = Template(sectionsTmpl).substitute(
                    section=str(sect)                    
                )
                sections += s

            footer = Template(footerTmpl).substitute(
                peMachineType=pe['pe-machine-type']
            )
          
            return header+langTypes+body1+imports+body2+resourceTypes\
            +body3+sections+footer
        else:
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
            
            header = Template(headerTmpl).substitute(
                sha1=answer['sha1'], 
                size=answer['size'], 
                positives=answer['positives'],
                total=answer['total'], 
                firstSeen=answer['first_seen'], 
                scanDate=answer['scan_date']
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