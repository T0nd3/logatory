from .apache import ApacheErrorParser
from .base import BaseParser
from .cef_leef import CEFParser, LEEFParser
from .detector import LogFormat
from .haproxy import HAProxyParser
from .json_lines import JsonLinesParser
from .logfmt import LogfmtParser
from .nginx import NginxCombinedParser
from .plaintext import PlaintextParser
from .plugins import get_plugin_parser
from .syslog import AuthLogParser, SyslogParser
from .traefik import TraefikParser


def get_parser(fmt: LogFormat | str, source: str) -> BaseParser:
    match fmt:
        case LogFormat.JSON_LINES:
            return JsonLinesParser(source)
        case LogFormat.NGINX_COMBINED:
            return NginxCombinedParser(source)
        case LogFormat.TRAEFIK:
            return TraefikParser(source)
        case LogFormat.APACHE_ERROR:
            return ApacheErrorParser(source)
        case LogFormat.HAPROXY:
            return HAProxyParser(source)
        case LogFormat.SYSLOG:
            return SyslogParser(source)
        case LogFormat.AUTH_LOG:
            return AuthLogParser(source)
        case LogFormat.LOGFMT:
            return LogfmtParser(source)
        case LogFormat.CEF:
            return CEFParser(source)
        case LogFormat.LEEF:
            return LEEFParser(source)
        case _:
            # A plugin-registered parser is identified by its name string
            # (what FormatDetector.detect returns for it). Fall back to
            # plaintext when nothing matches.
            name = fmt.value if isinstance(fmt, LogFormat) else str(fmt)
            plugin = get_plugin_parser(name)
            if plugin is not None:
                return plugin.factory(source)
            return PlaintextParser(source)
