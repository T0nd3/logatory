from .base import BaseParser
from .detector import LogFormat
from .json_lines import JsonLinesParser
from .logfmt import LogfmtParser
from .nginx import NginxCombinedParser
from .plaintext import PlaintextParser
from .syslog import AuthLogParser, SyslogParser


def get_parser(fmt: LogFormat, source: str) -> BaseParser:
    match fmt:
        case LogFormat.JSON_LINES:
            return JsonLinesParser(source)
        case LogFormat.NGINX_COMBINED:
            return NginxCombinedParser(source)
        case LogFormat.SYSLOG:
            return SyslogParser(source)
        case LogFormat.AUTH_LOG:
            return AuthLogParser(source)
        case LogFormat.LOGFMT:
            return LogfmtParser(source)
        case _:
            return PlaintextParser(source)
