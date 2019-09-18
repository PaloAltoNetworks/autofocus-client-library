import re
from .base import AutoFocusObject
from ..exceptions import _InvalidAnalysisData

# A dictionaries for mapping AutoFocus Analysis Response objects
# to their corresponding normalization classes and vice-versa
_analysis_2_class_map = {}
_class_2_analysis_map = {}


class AutoFocusAnalysis(AutoFocusObject):

    def __init__(self, obj_data):
        for k, v in list(obj_data.items()):
            setattr(self, k, v)

    @classmethod
    def _parse_auto_focus_response(cls, platform, resp_data):
        return cls(resp_data)


# apk_defined_activity
class ApkActivityAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, activity, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the activity observered
        self.activity = activity

    @classmethod
    def _parse_auto_focus_response(cls, platform, activity_data):

        line_parts = activity_data['line'].split(" , ")
        (activity) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (activity_data.get('b', 0),
                                             activity_data.get('m', 0),
                                             activity_data.get('g', 0))
        return cls(platform, activity, benign_c, malware_c, grayware_c)


# apk_defined_intent_filter
class ApkIntentFilterAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, intent, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the intent observered
        self.intent = intent

    @classmethod
    def _parse_auto_focus_response(cls, platform, intent_data):

        line_parts = intent_data['line'].split(" , ")
        (intent) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (intent_data.get('b', 0), intent_data.get('m', 0), intent_data.get('g', 0))
        return cls(platform, intent, benign_c, malware_c, grayware_c)


# apk_defined_receiver
class ApkReceiverAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, receiver, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the receiver used
        self.receiver = receiver

    @classmethod
    def _parse_auto_focus_response(cls, platform, rcv_data):

        line_parts = rcv_data['line'].split(" , ")
        (receiver) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (rcv_data.get('b', 0), rcv_data.get('m', 0), rcv_data.get('g', 0))
        return cls(platform, receiver, benign_c, malware_c, grayware_c)


# apk_suspicious_action_monitored
class ApkSuspiciousActivitySummary(AutoFocusAnalysis):

    def __init__(self, platform, description, detail, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string describing the activity
        self.description = description

        #: str: A string representing the details of the activity
        self.detail = detail

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (description, detail) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, description, detail, benign_c, malware_c, grayware_c)


# apk_packagename
class ApkPackage(AutoFocusAnalysis):

    def __init__(self, platform, name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string that is the name of the package for the APK
        self.name = name

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (name) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, name, benign_c, malware_c, grayware_c)


# apk_embedded_library
class ApkEmbeddedLibrary(AutoFocusAnalysis):

    def __init__(self, platform, name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string that is the name of the embedded library for the APK
        self.name = name

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (name) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, name, benign_c, malware_c, grayware_c)


# apk_app_icon
class ApkIcon(AutoFocusAnalysis):

    def __init__(self, platform, path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: the path to the icon for the app
        self.path = path

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (path) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, path, benign_c, malware_c, grayware_c)


# macro
class RelatedMacro(AutoFocusAnalysis):
    """
    Macro related to a sample
    """

    def __init__(self, platform, sha256, verdict, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: sha256 of the macro
        self.sha256 = sha256

        #: str: the verdict of the macro
        self.verdict = verdict.lower()

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (sha256, unknown_int, verdict) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, sha256, verdict, benign_c, malware_c, grayware_c)


# elf_domains
class ELFDomain(AutoFocusAnalysis):

    def __init__(self, platform, domain, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: domain
        self.domain = domain

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        domain = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, domain, benign_c, malware_c, grayware_c)


# elf_urls
class ELFURL(AutoFocusAnalysis):

    def __init__(self, platform, url, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: url
        self.url = url

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        url = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, url, benign_c, malware_c, grayware_c)


# elf_ip_address
class ELFIPAddress(AutoFocusAnalysis):

    def __init__(self, platform, ip_address, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: ip_address
        self.ip_address = ip_address

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        ip_address = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, ip_address, benign_c, malware_c, grayware_c)


# elf_functions
class ELFFunction(AutoFocusAnalysis):

    def __init__(self, platform, function, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: function
        self.function = function

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        function = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, function, benign_c, malware_c, grayware_c)


# elf_suspicous_behavior
class ELFSuspiciousBehavior(AutoFocusAnalysis):

    def __init__(self, platform, description, detail, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: description
        self.description = description

        #: str: detail, typically the syscall, file path, etc... depends on context
        self.detail = detail

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (description, detail) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, description, detail, benign_c, malware_c, grayware_c)


# elf_file_paths
class ELFFilePath(AutoFocusAnalysis):

    def __init__(self, platform, file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: file_path
        self.file_path = file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        file_path = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, file_path, benign_c, malware_c, grayware_c)


# elf_commands
class ELFCommands(AutoFocusAnalysis):

    def __init__(self, platform, command, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: command ran by the sample
        self.command = command

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        command = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, command, benign_c, malware_c, grayware_c)


# elf_file_activity
class ELFFileActivity(AutoFocusAnalysis):

    def __init__(self, platform, file_action, file_name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The attempted action taken on a file
        self.file_action = file_action

        #: str: The affected file's name
        self.file_name = file_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, file_data):
        line_parts = file_data['line'].split(" , ")
        if len(line_parts) == 2:
            (file_action, file_name) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))
        return cls(platform, file_action, file_name, benign_c, malware_c, grayware_c)


# elf_command_action
class ELFCommandAction(AutoFocusAnalysis):

    def __init__(self, platform, cmd, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: command ran by the sample
        self.cmd = cmd

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        cmd = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, cmd, benign_c, malware_c, grayware_c)


# elf_suspicious_action
class ELFSuspiciousActionMonitored(AutoFocusAnalysis):

    def __init__(self, platform, action, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: command ran by the sample
        self.action = action

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):
        line_parts = sensor_data['line'].split(" , ")
        action = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, action, benign_c, malware_c, grayware_c)


# version
class ApkVersion(AutoFocusAnalysis):

    def __init__(self, platform, version, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The version of the APK
        self.version = str(version)

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (version) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, version, benign_c, malware_c, grayware_c)


# apk_digital_signer
class DigitalSigner(AutoFocusAnalysis):

    def __init__(self, platform, signer, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the digital signer of the sample
        self.signer = signer

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (signer) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, signer, benign_c, malware_c, grayware_c)


# summary
class ApkEmbeddedFile(AutoFocusAnalysis):

    def __init__(self, platform, type, sha256, file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The file's sha256 sum
        self.sha256 = sha256.lower()

        #: str: The file's type (jpeg, png, etc..)
        self.type = type

        #: str: the file's path & name
        self.file_path = file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):
        line_parts = sensor_data['line'].split(" , ")
        (type, file_path, sha256) = line_parts[0:3]
        sha256 = sha256.split("=")[-1]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, type, sha256, file_path, benign_c, malware_c, grayware_c)


# summary
class AnalysisSummary(AutoFocusAnalysis):

    def __init__(self, platform, summary, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing a description of the behavior a malware exhibits
        self.summary = summary

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (summary) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, summary, benign_c, malware_c, grayware_c)


# apk_suspcious_pattern
class ApkSuspiciousPattern(AutoFocusAnalysis):

    def __init__(self, platform, description, pattern, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing a description of the behavior a malware exhibits
        self.description = description

        #: str: A string representing the pattern that the behavior a malware exhibits
        self.pattern = pattern

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (description, pattern) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, description, pattern, benign_c, malware_c, grayware_c)


# apk_app_name
class ApkAppName(AutoFocusAnalysis):

    def __init__(self, platform, name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The APK's App Name
        self.name = name

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (name) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, name, benign_c, malware_c, grayware_c)


# summary
class ApkRepackaged(AutoFocusAnalysis):

    def __init__(self, platform, repackaged, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: bool: Whether the APK has been repackaged or not
        self.repackaged = True if repackaged and repackaged == "True" else False

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (repackaged) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, repackaged, benign_c, malware_c, grayware_c)


# apk_certificate_id
# apk_cert_file
class ApkCertificate(AutoFocusAnalysis):
    """This class combines both apk_cert_file and apk_certificated_id analysis sections. Some samples only have
    apk_certificate_id, resulting in an object that only has an md5 sum, and the rest of hte attributes being null
    """

    def __init__(self, platform, benign, malware, grayware, md5, sha1=None, sha256=None, file_path=None,
                 owner=None, issuer=None):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the md5 of the APK cert
        self.md5 = md5.lower()

        #: Optional[str]: A string representing the sha1 of the APK cert
        self.sha1 = sha1.lower() if sha1 else None

        #: Optional[str]: A string representing the sha256 of the APK cert
        self.sha256 = sha256.lower() if sha256 else None

        #: Optional[str]: A string representing the owner of the APK certificate
        self.owner = owner

        #: Optional[str]: A string representing the issuer of the APK certificate
        self.issuer = issuer

        #: Optional[str]: A string representing the file path and name for the cert
        self.file_path = file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        # If this an apk_certificate_id record, it will just be the md5
        if len(sensor_data['line']) == 32:
            (md5) = sensor_data['line']
            (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0),
                                                 sensor_data.get('m', 0),
                                                 sensor_data.get('g', 0))
            return cls(platform, benign_c, malware_c, grayware_c, md5=md5)

        fields_match = re.search(r"certificate , ([^,]+) , owner=(.*) , issuer=(.*) ,"
                                 r" md5=(\S+) , sha1=(\S+) , sha256=(\S+)",
                                 sensor_data['line'])

        if not fields_match:
            raise _InvalidAnalysisData

        (file_path, owner, issuer, md5, sha1, sha256) = fields_match.groups()

        # If this is the apk_cert_file record, it will have more details
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, benign_c, malware_c, grayware_c,
                   file_path=file_path, md5=md5, sha1=sha1, sha256=sha256,
                   owner=owner, issuer=issuer)


# mac_embedded_url
class MacEmbeddedURL(AutoFocusAnalysis):

    def __init__(self, platform, url, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the URL embedded in the sample
        self.url = url

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (url) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, url, benign_c, malware_c, grayware_c)


# mac_embedded_file
class MacEmbeddedFile(AutoFocusAnalysis):

    def __init__(self, kwargs):

        #: str: The platform the sample analysis is from
        self.platform = kwargs['platform']

        #: str: sha256 of embedded file
        self.sha256 = kwargs['sha256']

        #: str: sha1 of embedded file
        self.sha1 = kwargs['sha1']

        #: str: path of embedded file
        self.path = kwargs['path']

        #: int: size of embedded file
        self.size = int(kwargs['size'])

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(kwargs['benign_count'])

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(kwargs['grayware_count'])

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(kwargs['malware_count'])

        #: str: name of embedded file
        self.name = kwargs['name']

        #: str: format of embedded file
        self.file_format = kwargs['file_format']

        #: str: sha1 of parent of this embedded file
        self.parent_sha1 = kwargs['parent_sha1']

        #: str: sha256 of parent of this embedded file
        self.parent_sha256 = kwargs['parent_sha256']

        #: str: path of parent of this file
        self.parent_path = kwargs['parent_path']

    @classmethod
    def _parse_auto_focus_response(cls, platform, service_data):

        line_parts = [l.strip() for l in service_data['line'].split(" , ")]
        data = {}
        for entry in line_parts:
            if entry:
                (k, v) = entry.split("=")
                if not v:
                    v = None
                if k == "format":
                    # don't mess with reserved words
                    k = "file_format"
                data[k] = v

        data['benign_count'] = service_data.get('b', 0)
        data['malware_count'] = service_data.get('m', 0)
        data['grayware_count'] = service_data.get('g', 0)
        data['platform'] = platform

        ma = cls(data)

        return ma


# apk_defined_sensor
class ApkSensorAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, sensor, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the sensor used
        self.sensor = sensor

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (sensor) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, sensor, benign_c, malware_c, grayware_c)


# apk_defined_service
class ApkServiceAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, service, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the service used
        self.service = service

    @classmethod
    def _parse_auto_focus_response(cls, platform, svc_data):

        line_parts = svc_data['line'].split(" , ")
        (service) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (svc_data.get('b', 0), svc_data.get('m', 0), svc_data.get('g', 0))
        return cls(platform, service, benign_c, malware_c, grayware_c)


# apk_embeded_url
class ApkEmbededUrlAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, url, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The URL accessed by the device
        self.url = url

        #: str: the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, perm_data):

        line_parts = perm_data['line'].split(" , ")
        (url, disasm_file_path) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (perm_data.get('b', 0), perm_data.get('m', 0), perm_data.get('g', 0))
        return cls(platform, url, disasm_file_path, benign_c, malware_c, grayware_c)


# apk_requested_permission
class ApkRequestedPermissionAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, permission, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the permission requested  by the sample
        self.permission = permission

    @classmethod
    def _parse_auto_focus_response(cls, platform, perm_data):

        line_parts = perm_data['line'].split(" , ")
        (permission) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (perm_data.get('b', 0), perm_data.get('m', 0), perm_data.get('g', 0))
        return cls(platform, permission, benign_c, malware_c, grayware_c)


# apk_sensitive_api_call
class ApkSensitiveApiCallAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, class_, method, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The name of the class accessed by the APK
        self.class_name = class_

        #: str: The name of the method accessed by the APK
        self.method = method

        #: Optional(str): the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, api_data):

        line_parts = api_data['line'].split(" , ")
        (class_, method) = line_parts[0].split(";->")
        class_ = class_.replace("/", ".")
        disasm_file_path = None
        if len(line_parts) > 1:
            disasm_file_path = line_parts[1]
        (benign_c, malware_c, grayware_c) = (api_data.get('b', 0), api_data.get('m', 0), api_data.get('g', 0))
        return cls(platform, class_, method, disasm_file_path, benign_c, malware_c, grayware_c)


# apk_suspicious_api_call
class ApkSuspiciousApiCallAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, class_, method, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The name of the class accessed by the APK
        self.class_name = class_

        #: str: The name of the method accessed by the APK
        self.method = method

        #: Optional(str): the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, api_data):

        line_parts = api_data['line'].split(" , ")
        (class_, method) = line_parts[0].split(";->")
        class_ = class_.replace("/", ".")
        disasm_file_path = None
        if len(line_parts) > 1:
            disasm_file_path = line_parts[1]
        (benign_c, malware_c, grayware_c) = (api_data.get('b', 0), api_data.get('m', 0), api_data.get('g', 0))
        return cls(platform, class_, method, disasm_file_path, benign_c, malware_c, grayware_c)


# apk_suspicious_file
class ApkSuspiciousFileAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, file_path, file_type, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The path to the file on the file system
        self.file_path = file_path

        #: str: the type of file that was identified
        self.file_type = file_type

    @classmethod
    def _parse_auto_focus_response(cls, platform, file_data):

        line_parts = file_data['line'].split(" , ")
        (file_path, file_type) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))
        return cls(platform, file_path, file_type, benign_c, malware_c, grayware_c)


# apk_suspicious_string
class ApkSuspiciousStringAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, string, file_name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The string that was identified as suspicious
        self.string = string

        #: str: The name of the file the suspicious string was found in
        self.file_name = file_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, string_data):

        line_parts = string_data['line'].split(" , ")
        (string, file_name) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (string_data.get('b', 0), string_data.get('m', 0), string_data.get('g', 0))
        return cls(platform, string, file_name, benign_c, malware_c, grayware_c)


# behavior
# {u'line': u'informational , 0.1 , A process running on the system may start additional processes to perform actions in the background. This behavior is common to legitimate software as well as malware. , process , 6 , Started a process'} # noqa
class BehaviorAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, risk, description):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: str: A string representing the risk of the behavior
        self.risk = risk

        #: str: A string describing the behavior
        self.description = description

    @classmethod
    def _parse_auto_focus_response(cls, platform, behavior_data):

        line_parts = behavior_data['line'].split(" , ")
        (risk, description) = [line_parts[i] for i in [0, 2]]

        ba = cls(platform, risk, description)

        return ba


# behavior_type
class BehaviorTypeAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, behavior):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: str: A string representing a behavior the sample exhibits
        self.behavior = behavior

    @classmethod
    def _parse_auto_focus_response(cls, platform, conn_data):

        ba = cls(platform, conn_data['line'])

        return ba


# connection
class ConnectionActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, src_port, dst_ip, dst_port, protocol, action, country_code,
                 benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The destination IP for the connection. Only valid for outbound connections
        self.dst_ip = dst_ip

        #: Optional(int): The destination port for the connection. Only valid for outbound connections
        self.dst_port = dst_port

        #: Optional(int): The source port for the connection. Only valid for listening connections
        self.src_port = src_port

        #: str: The protocol of the connection
        self.protocol = protocol

        #: Optional[str]: The name of the process that created the connection, when available
        self.process_name = process_name

        #: Optional[str]: The country code for the destionation IP, when available
        self.country_code = country_code

        #: str: The action related to the connection (listen or connect)
        self.action = action

    """
    Normalizing connection analysis is a nightmare. There are multiple formats you can expect:
     - <protocol>-connection , <dst_ip>:<dst_port> , <unknown_field> , <country_code>
     - <protocol>-connection , <dst_ip>:<dst_port> , <unknown_field>
     - bind , <unknown integer>
     - connect , <dst_ip>:<dst_port> , <unknown_field> , <country_code>
     - <protocol> , <dst_ip>:<dst_port> , <country_code>
     - <protocol>-listening , <src_port>
     - <protocol>-listening , <ApiFunctionName> , <src_port>
     - <process name>, <proto>-listening, RecvFrom, <Integer>
     - <process name>, <proto>-listening, Recv, <Integer>
    """
    @classmethod
    def _parse_auto_focus_response(cls, platform, conn_data):

        (dst_ip, src_port, dst_port, uk2, country_code) = (None, None, None, None, None)
        line_parts = conn_data['line'].split(" , ")

        if len(line_parts) >= 4:

            if "Recv" in line_parts and [v for v in line_parts if "-listening" in v]:
                raise _InvalidAnalysisData

            if len(line_parts) > 4:
                (process_name, protocol, dst_ip_port, uk2, country_code) = line_parts[0:5]
            else:
                (process_name, protocol, dst_ip_port, country_code) = line_parts[0:4]
            (dst_ip, dst_port) = dst_ip_port.split(":")
        elif len(line_parts) == 3:
            (process_name, protocol, src_port) = line_parts[0:3]

            if protocol == "bind":
                raise _InvalidAnalysisData()

        if protocol == "connect":
            protocol = "tcp"

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        if country_code == "" or country_code == "N/A":
            country_code = None

        (benign_c, malware_c, grayware_c) = (conn_data.get('b', 0), conn_data.get('m', 0), conn_data.get('g', 0))

        action = "connect"
        if protocol and "-" in protocol:
            (protocol, action) = protocol.split("-")

            if action == "connection":
                action = "connect"
            elif action == "listening":
                action = 'listen'
                if dst_port is not None and dst_ip is not None and src_port is None:
                    src_port = dst_port
                    dst_port = None
                    dst_ip = None
            else:
                pass
                # TODO remove this and throw an exception when we are confident about our normalization
                # sys.stderr.write("Unknown connection action {} -- tell BSMALL\n".format(action))

        if protocol:
            protocol = protocol.lower()

        # TODO remove this and throw an exception when we are confident about our normalization
        if protocol and protocol not in ('tcp', 'udp', 'icmp', 'gre'):
            pass
            # sys.stderr.write("Unknown protocol {} -- tell BSMALL\n".format(protocol))

        ca = cls(platform, process_name, src_port, dst_ip, dst_port, protocol, action, country_code, benign_c,
                 malware_c, grayware_c)

        return ca


# dns
class DnsActivity(AutoFocusAnalysis):

    def __init__(self, platform, query, response, type, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string of the query preformed
        self.query = query

        #: str: The response from the query performed
        self.response = response

        #: str: The type of request performed
        self.type = type

    @classmethod
    def _parse_auto_focus_response(cls, platform, dns_data):

        line_parts = dns_data['line'].split(" , ")
        (query, response, type) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (dns_data.get('b', 0), dns_data.get('m', 0), dns_data.get('g', 0))

        da = cls(platform, query, response, type, benign_c, malware_c, grayware_c)

        return da


# file
class FileActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, file_action, file_name, benign, malware, grayware):
        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the file
        self.process_name = process_name

        #: str: The attempted action taken on a file
        self.file_action = file_action

        #: Optional[str]: The affected file's name
        self.file_name = file_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, file_data):

        line_parts = file_data['line'].split(" , ")
        if len(line_parts) < 3:
            (process_name, file_action) = line_parts[0:2]
            file_name = None
        else:
            (process_name, file_action, file_name) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        fa = cls(platform, process_name, file_action, file_name, benign_c, malware_c, grayware_c)

        return fa


# http
class HttpActivity(AutoFocusAnalysis):

    def __init__(self, platform, host, method, url, user_agent, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The host the HTTP connection was made to
        self.host = host

        #: str: The method used in the requesty
        self.method = method

        #: str: The url of the request
        self.url = url

        #: str: The user agent of the request
        self.user_agent = user_agent

    @classmethod
    def _parse_auto_focus_response(cls, platform, http_data):

        line_parts = http_data['line'].split(" , ", 3)
        (host, method, url, user_agent) = line_parts[0:4]
        (benign_c, malware_c, grayware_c) = (http_data.get('b', 0), http_data.get('m', 0), http_data.get('g', 0))

        ha = cls(platform, host, method, url, user_agent, benign_c, malware_c, grayware_c)

        return ha


# japi
class JavaApiActivity(AutoFocusAnalysis):

    def __init__(self, platform, activity, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        # TODO: Very generic. Needs more context
        #: str: A string representing java API activity
        self.activity = activity

    @classmethod
    def _parse_auto_focus_response(cls, platform, japi_data):

        (benign_c, malware_c, grayware_c) = (japi_data.get('b', 0), japi_data.get('m', 0), japi_data.get('g', 0))

        ja = cls(platform, japi_data['line'], benign_c, malware_c, grayware_c)

        return ja


# mutex
class MutexActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, function_name, mutex_name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the mutex
        self.process_name = process_name

        #: str: The function called to affect the mutex (At the time of this writing, have only seen CreateMutexW)
        self.function_name = function_name

        #: str: THe name of the mutex affected
        self.mutex_name = mutex_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, mutex_data):

        (process_name, function_name, mutex_name) = mutex_data['line'].split(" , ")
        (benign_c, malware_c, grayware_c) = (mutex_data.get('b', 0), mutex_data.get('m', 0), mutex_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, function_name, mutex_name, benign_c, malware_c, grayware_c)

        return ma


# misc
class ApiActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, function_name, function_arguments, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the mutex
        self.process_name = process_name

        #: str: The function called
        self.function_name = function_name

        #: array[str]: arguments passed to the function
        self.function_arguments = function_arguments

    @classmethod
    def _parse_auto_focus_response(cls, platform, misc_data):

        if not misc_data['line']:
            raise _InvalidAnalysisData()

        line_parts = misc_data['line'].split(" , ")
        (process_name, function_name) = line_parts[0:2]
        func_args = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (misc_data.get('b', 0), misc_data.get('m', 0), misc_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, function_name, func_args, benign_c, malware_c, grayware_c)

        return ma


# process
class ProcessActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the process
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: array[str]: arguments passed to the function
        self.parameters = parameters

    @classmethod
    def _parse_auto_focus_response(cls, platform, misc_data):

        line_parts = misc_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (misc_data.get('b', 0), misc_data.get('m', 0), misc_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, parameters, benign_c, malware_c, grayware_c)

        return ma


# registry
class RegistryActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, registry_key, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the registry
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: str: The registry key being affected
        self.registry_key = registry_key

        #: array[str]: arguments passed to the function
        self.parameters = parameters

    @classmethod
    def _parse_auto_focus_response(cls, platform, registry_data):

        line_parts = registry_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]

        if len(line_parts) < 3:
            raise _InvalidAnalysisData()

        registry_key = line_parts[2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (registry_data.get('b', 0),
                                             registry_data.get('m', 0),
                                             registry_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, registry_key, parameters, benign_c, malware_c, grayware_c)

        return ma


# service
class ServiceActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the service
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: array[str]: arguments passed to the function
        self.parameters = parameters

    @classmethod
    def _parse_auto_focus_response(cls, platform, service_data):

        line_parts = service_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (service_data.get('b', 0),
                                             service_data.get('m', 0),
                                             service_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, parameters, benign_c, malware_c, grayware_c)

        return ma


# user_agent
class UserAgentFragment(AutoFocusAnalysis):

    def __init__(self, platform, fragment, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing a fragment of the user agent (stripping fluff, ie "Mozilla/5.0")
        self.fragment = fragment

    @classmethod
    def _parse_auto_focus_response(cls, platform, ua_data):

        (benign_c, malware_c, grayware_c) = (ua_data.get('b', 0), ua_data.get('m', 0), ua_data.get('g', 0))

        ba = cls(platform, ua_data['line'], benign_c, malware_c, grayware_c)

        return ba


class PEMetaData(AutoFocusAnalysis):

    _section = "metadata_sections"

    def __init__(self, platform, name, virtual_address, virtual_size, raw_size, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The name of the section
        self.name = name

        #: int: virtual address
        self.virtual_address = int(virtual_address)

        #: int: virtual size
        self.virtual_size = int(virtual_size)

        #: int: raw size
        self.raw_size = int(raw_size)

    @classmethod
    def _parse_auto_focus_response(cls, platform, pe_meta_data):

        (benign_c, malware_c, grayware_c) = (pe_meta_data.get('b', 0),
                                             pe_meta_data.get('m', 0),
                                             pe_meta_data.get('g', 0))

        ba = cls(platform, *pe_meta_data['line'].split(","), benign_c, malware_c, grayware_c)

        return ba


_analysis_2_class_map['apk_defined_activity'] = ApkActivityAnalysis
_analysis_2_class_map['apk_defined_intent_filter'] = ApkIntentFilterAnalysis
_analysis_2_class_map['apk_defined_receiver'] = ApkReceiverAnalysis
_analysis_2_class_map['apk_defined_sensor'] = ApkSensorAnalysis
_analysis_2_class_map['apk_defined_service'] = ApkServiceAnalysis
_analysis_2_class_map['apk_embeded_url'] = ApkEmbededUrlAnalysis
_analysis_2_class_map['apk_requested_permission'] = ApkRequestedPermissionAnalysis
_analysis_2_class_map['apk_sensitive_api_call'] = ApkSensitiveApiCallAnalysis
_analysis_2_class_map['apk_suspicious_api_call'] = ApkSuspiciousApiCallAnalysis
_analysis_2_class_map['apk_suspicious_file'] = ApkSuspiciousFileAnalysis
_analysis_2_class_map['apk_suspicious_string'] = ApkSuspiciousStringAnalysis
_analysis_2_class_map['mac_embedded_url'] = MacEmbeddedURL
_analysis_2_class_map['mac_embedded_file'] = MacEmbeddedFile
_analysis_2_class_map['apk_suspicious_action_monitored'] = ApkSuspiciousActivitySummary
_analysis_2_class_map['summary'] = AnalysisSummary
_analysis_2_class_map['apk_app_name'] = ApkAppName
_analysis_2_class_map['apk_certificate_id'] = ApkCertificate
_analysis_2_class_map['apk_cert_file'] = ApkCertificate
_analysis_2_class_map['apk_digital_signer'] = DigitalSigner
_analysis_2_class_map['apk_packagename'] = ApkPackage
_analysis_2_class_map['apk_embedded_library'] = ApkEmbeddedLibrary
_analysis_2_class_map['apk_isrepackaged'] = ApkRepackaged
_analysis_2_class_map['apk_version_num'] = ApkVersion
_analysis_2_class_map['behavior'] = BehaviorAnalysis
_analysis_2_class_map['behavior_type'] = BehaviorTypeAnalysis
_analysis_2_class_map['connection'] = ConnectionActivity
_analysis_2_class_map['dns'] = DnsActivity
_analysis_2_class_map['file'] = FileActivity
_analysis_2_class_map['http'] = HttpActivity
_analysis_2_class_map['japi'] = JavaApiActivity
_analysis_2_class_map['mutex'] = MutexActivity
_analysis_2_class_map['metadata_sections'] = PEMetaData
_analysis_2_class_map['misc'] = ApiActivity
_analysis_2_class_map['process'] = ProcessActivity
_analysis_2_class_map['registry'] = RegistryActivity
_analysis_2_class_map['service'] = ServiceActivity
_analysis_2_class_map['user_agent'] = UserAgentFragment
_analysis_2_class_map['apk_suspicious_pattern'] = ApkSuspiciousPattern
_analysis_2_class_map['apk_app_icon'] = ApkIcon
_analysis_2_class_map['apk_internal_file'] = ApkEmbeddedFile
_analysis_2_class_map['elf_commands'] = ELFCommands
_analysis_2_class_map['elf_file_paths'] = ELFFilePath
_analysis_2_class_map['elf_suspicious_behavior'] = ELFSuspiciousBehavior
_analysis_2_class_map['elf_functions'] = ELFFunction
_analysis_2_class_map['elf_ip_address'] = ELFIPAddress
_analysis_2_class_map['elf_domains'] = ELFDomain
_analysis_2_class_map['elf_urls'] = ELFURL
_analysis_2_class_map['elf_file_activity'] = ELFFileActivity
_analysis_2_class_map['elf_command_action'] = ELFCommandAction
_analysis_2_class_map['elf_suspicious_action'] = ELFSuspiciousActionMonitored
_analysis_2_class_map['macro'] = RelatedMacro

for k, v in list(_analysis_2_class_map.items()):
    _class_2_analysis_map[v] = k
    v.__autofocus_section = k
