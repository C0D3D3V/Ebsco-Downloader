import collections
import contextlib
import email.utils
import html
import http
import io
import itertools
import logging
import math
import os
import re
import ssl
import sys
import time
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Dict
from urllib.parse import quote

import requests
import urllib3
from aiohttp.cookiejar import CookieJar
from lxml import etree
from requests.utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths


def check_verbose() -> bool:
    """Return if the verbose mode is active"""
    return '-v' in sys.argv or '--verbose' in sys.argv


def check_debug() -> bool:
    """Return if the debugger is currently active"""
    return 'pydevd' in sys.modules or (hasattr(sys, 'gettrace') and sys.gettrace() is not None)


def parse_xml_string(s):
    parser = etree.XMLParser(recover=True, resolve_entities=False)
    try:
        tree = etree.parse(io.BytesIO(s.encode('utf-8')), parser=parser)
    except:
        tree = etree.parse(io.BytesIO(s), parser=parser)

    return tree


def format_seconds(seconds):
    (mins, secs) = divmod(seconds, 60)
    (hours, mins) = divmod(mins, 60)
    if hours > 99:
        return '--:--:--'
    if hours == 0:
        return f'{int(mins):02d}:{int(secs):02d}'
    return f'{int(hours):02d}:{int(mins):02d}:{int(secs):02d}'


def calc_speed(start, now, byte_count):
    dif = now - start
    if byte_count <= 0 or dif < 0.001:  # One millisecond
        return None
    return float(byte_count) / dif


def format_speed(speed):
    if speed is None:
        return f"{'---b/s':10}"
    speed_text = format_bytes(speed) + '/s'
    return f'{speed_text:10}'


async def run_with_final_message(load_function, entry: Dict, message: str, *format_args):
    result = await load_function(entry)
    logging.info(message, *format_args)
    return result


def get_nested(from_dict: Dict, key: str, default=None):
    keys = key.split('.')
    try:
        result = from_dict
        for key in keys:
            result = result[key]
        return result
    except KeyError:
        return default


def timeconvert(timestr):
    """Convert RFC 2822 defined time string into system timestamp"""
    timestamp = None
    timetuple = email.utils.parsedate_tz(timestr)
    if timetuple is not None:
        timestamp = email.utils.mktime_tz(timetuple)
    return timestamp


def float_or_none(v, scale=1, invscale=1, default=None):
    if v is None:
        return default
    try:
        return float(v) * invscale / scale
    except (ValueError, TypeError):
        return default


def format_decimal_suffix(num, fmt='%d%s', *, factor=1000):
    """Formats numbers with decimal sufixes like K, M, etc"""
    num, factor = float_or_none(num), float(factor)
    if num is None or num < 0:
        return None
    POSSIBLE_SUFFIXES = 'kMGTPEZY'
    exponent = 0 if num == 0 else min(int(math.log(num, factor)), len(POSSIBLE_SUFFIXES))
    suffix = ['', *POSSIBLE_SUFFIXES][exponent]
    if factor == 1024:
        suffix = {'k': 'Ki', '': ''}.get(suffix, f'{suffix}i')
    converted = num / (factor**exponent)
    return fmt % (converted, suffix)


def format_bytes(bytes_to_format):
    return format_decimal_suffix(bytes_to_format, '%.2f%sB', factor=1024) or 'N/A'


# needed for sanitizing filenames in restricted mode
ACCENT_CHARS = dict(
    zip(
        'ÂÃÄÀÁÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖŐØŒÙÚÛÜŰÝÞßàáâãäåæçèéêëìíîïðñòóôõöőøœùúûüűýþÿ',
        itertools.chain(
            'AAAAAA',
            ['AE'],
            'CEEEEIIIIDNOOOOOOO',
            ['OE'],
            'UUUUUY',
            ['TH', 'ss'],
            'aaaaaa',
            ['ae'],
            'ceeeeiiiionooooooo',
            ['oe'],
            'uuuuuy',
            ['th'],
            'y',
        ),
    )
)

NO_DEFAULT = object()


def is_path_like(f):
    return isinstance(f, (str, bytes, os.PathLike))


def str_or_none(v, default=None):
    return default if v is None else str(v)


def convert_to_aiohttp_cookie_jar(mozilla_cookie_jar: http.cookiejar.MozillaCookieJar):
    """
    Convert an http.cookiejar.MozillaCookieJar that uses a Netscape HTTP Cookie File to an aiohttp.cookiejar.CookieJar
    Tested with aiohttp v3.8.4
    """
    aiohttp_cookie_jar = CookieJar(unsafe=True)  # unsafe = Allow also cookies for IPs

    # pylint: disable=protected-access
    for cookie_domain, domain_cookies in mozilla_cookie_jar._cookies.items():
        for cookie_path, path_cookies in domain_cookies.items():
            for cookie_name, cookie in path_cookies.items():
                # cookie_name is cookie.name; cookie_path is cookie.path; cookie_domain is cookie.domain
                morsel = http.cookies.Morsel()
                morsel.update(
                    {
                        "expires": cookie.expires,
                        "path": cookie.path,
                        "comment": cookie.comment,
                        "domain": cookie.domain,
                        # "max-age"  : "Max-Age",
                        "secure": cookie.secure,
                        # "httponly": "HttpOnly",
                        "version": cookie.version,
                        # "samesite": "SameSite",
                    }
                )
                # pylint: disable=protected-access
                morsel.set(cookie.name, cookie.value, http.cookies._quote(cookie.value))
                aiohttp_cookie_jar._cookies[(cookie_domain, cookie_path)][cookie_name] = morsel

    return aiohttp_cookie_jar


class SimpleCookieJar(http.cookiejar.MozillaCookieJar):
    """
    Taken from yt-dlp: Last update 9. Sep. 2022
    See [1] for cookie file format.

    1. https://curl.haxx.se/docs/http-cookies.html
    """

    _HTTPONLY_PREFIX = '#HttpOnly_'
    _ENTRY_LEN = 7
    _HEADER = '''# Netscape HTTP Cookie File
# This file is generated.  Do not edit.

'''
    _CookieFileEntry = collections.namedtuple(
        'CookieFileEntry', ('domain_name', 'include_subdomains', 'path', 'https_only', 'expires_at', 'name', 'value')
    )

    def __init__(self, filename=None, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        if is_path_like(filename):
            filename = os.fspath(filename)
        self.filename = filename

    @staticmethod
    def _true_or_false(cndn):
        return 'TRUE' if cndn else 'FALSE'

    @contextlib.contextmanager
    def open(self, file, *, write=False):
        if is_path_like(file):
            with open(file, 'w' if write else 'r', encoding='utf-8') as f:
                yield f
        else:
            if write:
                file.truncate(0)
            yield file

    def _really_save(self, f, ignore_discard=False, ignore_expires=False):
        now = time.time()
        for cookie in self:
            if not ignore_discard and cookie.discard or not ignore_expires and cookie.is_expired(now):
                continue
            name, value = cookie.name, cookie.value
            if value is None:
                # cookies.txt regards 'Set-Cookie: foo' as a cookie
                # with no name, whereas http.cookiejar regards it as a
                # cookie with no value.
                name, value = '', name
            f.write(
                '%s\n'
                % '\t'.join(
                    (
                        cookie.domain,
                        self._true_or_false(cookie.domain.startswith('.')),
                        cookie.path,
                        self._true_or_false(cookie.secure),
                        str_or_none(cookie.expires, default=''),
                        name,
                        value,
                    )
                )
            )

    def save(self, filename=None, *args, **kwargs):
        """
        Save cookies to a file.
        Code is taken from CPython 3.6
        https://github.com/python/cpython/blob/8d999cbf4adea053be6dbb612b9844635c4dfb8e/Lib/http/cookiejar.py#L2091-L2117
        """

        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError(http.cookiejar.MISSING_FILENAME_TEXT)

        # Store session cookies with `expires` set to 0 instead of an empty string
        for cookie in self:
            if cookie.expires is None:
                cookie.expires = 0

        with self.open(filename, write=True) as f:
            f.write(self._HEADER)
            self._really_save(f, *args, **kwargs)

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):
        """Load cookies from a file."""
        if filename is None:
            if self.filename is not None:
                filename = self.filename
            else:
                raise ValueError(http.cookiejar.MISSING_FILENAME_TEXT)

        def prepare_line(line):
            if line.startswith(self._HTTPONLY_PREFIX):
                line = line[len(self._HTTPONLY_PREFIX) :]
            # comments and empty lines are fine
            if line.startswith('#') or not line.strip():
                return line
            cookie_list = line.split('\t')
            if len(cookie_list) != self._ENTRY_LEN:
                raise http.cookiejar.LoadError('invalid length %d' % len(cookie_list))
            cookie = self._CookieFileEntry(*cookie_list)
            if cookie.expires_at and not cookie.expires_at.isdigit():
                raise http.cookiejar.LoadError('invalid expires at %s' % cookie.expires_at)
            return line

        cf = io.StringIO()
        with self.open(filename) as input_file:
            for line in input_file:
                try:
                    cf.write(prepare_line(line))
                except http.cookiejar.LoadError as cookie_err:
                    if f'{line.strip()} '[0] in '[{"':
                        raise http.cookiejar.LoadError(
                            'Cookies file must be Netscape formatted, not JSON. See  '
                            'https://github.com/C0D3D3V/Moodle-DL/wiki/Use-cookies-when-downloading'
                        )
                    Log.info(f'WARNING: Skipping cookie file entry due to {cookie_err}: {line!r}')
                    continue
        cf.seek(0)
        self._really_load(cf, filename, ignore_discard, ignore_expires)
        # Session cookies are denoted by either `expires` field set to
        # an empty string or 0. MozillaCookieJar only recognizes the former
        # (see [1]). So we need force the latter to be recognized as session
        # cookies on our own.
        # Session cookies may be important for cookies-based authentication,
        # e.g. usually, when user does not check 'Remember me' check box while
        # logging in on a site, some important cookies are stored as session
        # cookies so that not recognizing them will result in failed login.
        # 1. https://bugs.python.org/issue17164
        for cookie in self:
            # Treat `expires=0` cookies as session cookies
            if cookie.expires == 0:
                cookie.expires = None
                cookie.discard = True


class Timer:
    '''
    Timing Context Manager
    Can be used for future speed comparisons, like this:

    with Timer() as t:
        Do.stuff()
    print(f'Do.stuff() took:\t {t.duration:.3f} \tseconds.')
    '''

    def __init__(self, nanoseconds=False):
        self.start = 0.0
        self.duration = 0.0
        self.nanoseconds = nanoseconds

    def __enter__(self):
        if self.nanoseconds:
            self.start = time.perf_counter_ns()
        else:
            self.start = time.time()
        return self

    def __exit__(self, *args):
        if self.nanoseconds:
            end = time.perf_counter_ns()
            self.duration = (end - self.start) * 10**-9  # 1 nano-sec = 10^-9 sec
        else:
            end = time.time()
            self.duration = end - self.start


PathParts = collections.namedtuple('PathParts', ('dir_name', 'file_name', 'file_extension'))


class PathTools:
    """A set of methods to create correct paths."""

    restricted_filenames = False

    @staticmethod
    def to_valid_name(name: str, is_file: bool, max_length: int = 200) -> str:
        """
        Filtering invalid characters in filenames and paths.

        @param name: The string that will go through the filtering
        @param is_file: If true, it is tried to keep the extension of the file name
        @param max_length: Most filesystems allow a max filename length of 255 chars,
                            we default use a shorter name to allow long extensions
        @return: The filtered string, that can be used as a filename.
        """

        if name is None:
            return None

        name = html.unescape(name)

        name = name.replace('\n', ' ')
        name = name.replace('\r', ' ')
        name = name.replace('\t', ' ')
        name = name.replace('\xad', '')
        while '  ' in name:
            name = name.replace('  ', ' ')
        name = PathTools.sanitize_filename(name, PathTools.restricted_filenames)
        name = name.strip('. ')
        name = name.strip()
        name = PathTools.truncate_filename(name, is_file, max_length)

        return name

    @staticmethod
    def truncate_filename(name: str, is_file: bool, max_length: int):
        if len(name) > max_length:
            if not is_file:
                name = PathTools.truncate_name(name, max_length)
            else:
                stem, ext = PathTools.get_file_stem_and_ext(name)
                ext_len = len(ext)
                if ext is None or ext_len == 0 or ext_len > 20:
                    # extensions longer then 20 characters are probably no extensions
                    name = PathTools.truncate_name(name, max_length)
                else:
                    stem = PathTools.truncate_name(stem, max_length - ext_len - 1)
                    name = f'{stem}.{ext}'
        return name

    @staticmethod
    def truncate_name(name: str, max_length: int):
        if PathTools.restricted_filenames:
            name = name[: max_length - 3] + '...'
        else:
            name = name[: max_length - 1] + '…'
        return name

    @staticmethod
    def remove_start(s, start):
        return s[len(start) :] if s is not None and s.startswith(start) else s

    @staticmethod
    def sanitize_filename(s, restricted=False, is_id=NO_DEFAULT):
        """Sanitizes a string so it could be used as part of a filename.
        @param restricted   Use a stricter subset of allowed characters
        @param is_id        Whether this is an ID that should be kept unchanged if possible.
                            If unset, yt-dlp's new sanitization rules are in effect
        """
        if s == '':
            return ''

        def replace_insane(char):
            if restricted and char in ACCENT_CHARS:
                return ACCENT_CHARS[char]
            elif not restricted and char == '\n':
                return '\0 '
            elif is_id is NO_DEFAULT and not restricted and char in '"*:<>?|/\\':
                # Replace with their full-width unicode counterparts
                return {'/': '\u29F8', '\\': '\u29f9'}.get(char, chr(ord(char) + 0xFEE0))
            elif char == '?' or ord(char) < 32 or ord(char) == 127:
                return ''
            elif char == '"':
                return '' if restricted else '\''
            elif char == ':':
                return '\0_\0-' if restricted else '\0 \0-'
            elif char in '\\/|*<>':
                return '\0_'
            if restricted and (char in '!&\'()[]{}$;`^,#' or char.isspace() or ord(char) > 127):
                return '\0_'
            return char

        if restricted and is_id is NO_DEFAULT:
            s = unicodedata.normalize('NFKC', s)
        s = re.sub(r'[0-9]+(?::[0-9]+)+', lambda m: m.group(0).replace(':', '_'), s)  # Handle timestamps
        result = ''.join(map(replace_insane, s))
        if is_id is NO_DEFAULT:
            result = re.sub(r'(\0.)(?:(?=\1)..)+', r'\1', result)  # Remove repeated substitute chars
            STRIP_RE = r'(?:\0.|[ _-])*'
            result = re.sub(f'^\0.{STRIP_RE}|{STRIP_RE}\0.$', '', result)  # Remove substitute chars from start/end
        result = result.replace('\0', '') or '_'

        if not is_id:
            while '__' in result:
                result = result.replace('__', '_')
            result = result.strip('_')
            # Common case of "Foreign band name - English song title"
            if restricted and result.startswith('-_'):
                result = result[2:]
            if result.startswith('-'):
                result = '_' + result[len('-') :]
            result = result.lstrip('.')
            if not result:
                result = '_'
        return result

    @staticmethod
    def sanitize_path(path: str):
        """
        @param path: A path to sanitize.
        @return: A path where every part was sanitized using to_valid_name.
        """
        drive_or_unc, _ = os.path.splitdrive(path)
        norm_path = os.path.normpath(PathTools.remove_start(path, drive_or_unc)).split(os.path.sep)
        if drive_or_unc:
            norm_path.pop(0)

        sanitized_path = [
            path_part if path_part in ['.', '..'] else PathTools.to_valid_name(path_part, is_file=False)
            for path_part in norm_path
        ]

        if drive_or_unc:
            sanitized_path.insert(0, drive_or_unc + os.path.sep)
        return os.path.join(*sanitized_path)

    @staticmethod
    def path_of_book(storage_path: str, book_title: str) -> Path:
        """
        @param storage_path: The path where all files should be stored.
        @param title: The name of the book.
        @return: A path where the file should be saved.
        """
        path = Path(storage_path) / PathTools.to_valid_name(book_title, is_file=False)
        return path

    @staticmethod
    def remove_file(file_path: str):
        if file_path is not None and os.path.exists(file_path):
            os.unlink(file_path)

    @staticmethod
    def get_abs_path(path: str):
        return str(Path(path).resolve())

    @staticmethod
    def make_path(path: str, *filenames: str):
        result_path = Path(path)
        for filename in filenames:
            result_path = result_path / filename
        return str(result_path)

    @staticmethod
    def make_base_dir(path_to_file: str):
        Path(path_to_file).parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def make_dirs(path_to_dir: str):
        Path(path_to_dir).mkdir(parents=True, exist_ok=True)

    @classmethod
    def win_max_path_length_workaround(cls, path):
        # Working around MAX_PATH limitation on Windows (see
        # http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx)
        if os.name == 'nt' or sys.platform in ['win32', 'cygwin']:
            abs_file_path = cls.get_abs_path(path)
            path = '\\\\?\\' + abs_file_path
        return path

    @staticmethod
    def get_user_config_directory():
        """Returns a platform-specific root directory for user config settings."""
        # On Windows, prefer %LOCALAPPDATA%, then %APPDATA%, since we can expect the
        # AppData directories to be ACLed to be visible only to the user and admin
        # users (https://stackoverflow.com/a/7617601/1179226). If neither is set,
        # return None instead of falling back to something that may be world-readable.
        if os.name == "nt":
            appdata = os.getenv("LOCALAPPDATA")
            if appdata:
                return appdata
            appdata = os.getenv("APPDATA")
            if appdata:
                return appdata
            return None
        # On non-windows, use XDG_CONFIG_HOME if set, else default to ~/.config.
        xdg_config_home = os.getenv("XDG_CONFIG_HOME")
        if xdg_config_home:
            return xdg_config_home
        return os.path.join(os.path.expanduser("~"), ".config")

    @staticmethod
    def get_user_data_directory():
        """Returns a platform-specific root directory for user application data."""
        if os.name == "nt":
            appdata = os.getenv("LOCALAPPDATA")
            if appdata:
                return appdata
            appdata = os.getenv("APPDATA")
            if appdata:
                return appdata
            return None
        # On non-windows, use XDG_DATA_HOME if set, else default to ~/.config.
        xdg_config_home = os.getenv("XDG_DATA_HOME")
        if xdg_config_home:
            return xdg_config_home
        return os.path.join(os.path.expanduser("~"), ".local/share")

    @staticmethod
    def get_project_data_directory():
        """
        Returns an Path object to the project config directory
        """
        data_dir = Path(PathTools.get_user_data_directory()) / "ebsco-dl"
        if not data_dir.is_dir():
            data_dir.mkdir(parents=True, exist_ok=True)
        return str(data_dir)

    @staticmethod
    def get_project_config_directory():
        """
        Returns an Path object to the project config directory
        """
        config_dir = Path(PathTools.get_user_config_directory()) / "ebsco-dl"
        if not config_dir.is_dir():
            config_dir.mkdir(parents=True, exist_ok=True)
        return str(config_dir)

    @staticmethod
    def get_unused_filename(destination: str, filename: str, file_extension: str, start_clear=True):
        count = 0
        if start_clear:
            new_file_path = str(Path(destination) / f'{filename}.{file_extension}')
        else:
            new_file_path = str(Path(destination) / f'{filename}_{count:02d}.{file_extension}')
        while os.path.exists(new_file_path):
            count += 1
            new_file_path = str(Path(destination) / f'{filename}_{count:02d}.{file_extension}')

        return new_file_path

    @staticmethod
    def get_path_parts(file_path: str) -> PathParts:
        """
        @return: PathParts - File extension is without a dot!
        """
        destination = os.path.dirname(file_path)
        filename, file_extension = os.path.splitext(os.path.basename(file_path))
        if file_extension.startswith('.'):
            file_extension = file_extension[1:]
        return PathParts(destination, filename, file_extension)

    @classmethod
    def get_unused_file_path(cls, file_path: str, start_clear=True):
        destination, filename, file_extension = cls.get_path_parts(file_path)
        return cls.get_unused_filename(destination, filename, file_extension, start_clear)

    @classmethod
    def touch_file(cls, file_path: str):
        open(file_path, 'a', encoding='utf-8').close()

    @staticmethod
    def get_file_exts(filename: str) -> (str, str):
        file_splits = filename.rsplit('.', 2)
        if len(file_splits) == 2:
            return None, file_splits[-1].lower()
        if len(file_splits) == 3:
            return file_splits[-2].lower(), file_splits[-1].lower()
        return None, None

    @staticmethod
    def get_file_ext(filename: str) -> str:
        file_splits = filename.rsplit('.', 1)
        if len(file_splits) == 2:
            return file_splits[-1].lower()
        return None

    @staticmethod
    def get_file_stem_and_ext(filename: str) -> (str, str):
        file_splits = filename.rsplit('.', 1)
        if len(file_splits) == 2:
            return file_splits[0], file_splits[1]
        return file_splits[0], None

    @staticmethod
    def get_cookies_path(storage_path: str) -> str:
        return PathTools.make_path(storage_path, 'Cookies.txt')


class SslHelper:
    warned_about_certifi = False

    @classmethod
    def load_default_certs(cls, ssl_context: ssl.SSLContext):
        cert_loc = extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)

        if not cert_loc or not os.path.exists(cert_loc):
            if not cls.warned_about_certifi:
                Log.warning(f"Certifi could not find a suitable TLS CA certificate bundle, invalid path: {cert_loc}")
                cls.warned_about_certifi = True
            ssl_context.load_default_certs()
        else:
            if not os.path.isdir(cert_loc):
                ssl_context.load_verify_locations(cafile=cert_loc)
            else:
                ssl_context.load_verify_locations(capath=cert_loc)

    @classmethod
    @lru_cache(maxsize=4)
    def get_ssl_context(cls, skip_cert_verify: bool, allow_insecure_ssl: bool, use_simple_ciphers: bool):
        if not skip_cert_verify:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            cls.load_default_certs(ssl_context)
        else:
            ssl_context = ssl._create_unverified_context()  # pylint: disable=protected-access

        if allow_insecure_ssl:
            # This allows connections to legacy insecure servers
            # https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_options.html#SECURE-RENEGOTIATION
            # Be warned the insecure renegotiation allows an attack, see:
            # https://nvd.nist.gov/vuln/detail/CVE-2009-3555
            ssl_context.options |= 0x4  # set ssl.OP_LEGACY_SERVER_CONNECT bit
        if use_simple_ciphers:
            pass
            # ssl_context.options = 0
            # ssl_context.set_ciphers("AES256-SHA")

        return ssl_context

    class CustomHttpAdapter(requests.adapters.HTTPAdapter):
        '''
        Transport adapter that allows us to use custom ssl_context.
        See https://stackoverflow.com/a/71646353 for more details.
        '''

        def __init__(self, ssl_context=None, **kwargs):
            self.ssl_context = ssl_context
            super().__init__(**kwargs)

        def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
            self.poolmanager = urllib3.poolmanager.PoolManager(
                num_pools=connections, maxsize=maxsize, block=block, ssl_context=self.ssl_context, **pool_kwargs
            )

    @classmethod
    def custom_requests_session(cls, skip_cert_verify: bool, allow_insecure_ssl: bool, use_simple_ciphers: bool):
        """
        Return a new requests session with custom SSL context
        """
        session = requests.Session()
        ssl_context = cls.get_ssl_context(skip_cert_verify, allow_insecure_ssl, use_simple_ciphers)
        session.mount('https://', cls.CustomHttpAdapter(ssl_context))
        session.verify = not skip_cert_verify
        return session


class ProcessLock:
    """
    A very simple lock mechanism to prevent multiple downloader being started for the same EBSCO.

    The functions are not resistant to high frequency calls.
    Raise conditions will occur!
    """

    class LockError(Exception):
        """An Exception which gets thrown if a Downloader is already running."""

        pass

    @staticmethod
    def lock(dir_path: str):
        """
        Test if a lock is already set in a directory, if not it creates the lock.
        """
        path = Path(dir_path) / 'running.lock'
        if Path(path).exists():
            raise ProcessLock.LockError(
                f'A downloader is already running. Delete {str(path)} if you think this is wrong.'
            )
        Path(path).touch()

    @staticmethod
    def unlock(dir_path: str):
        """Remove a lock in a directory."""
        path = Path(dir_path) / 'running.lock'
        try:
            Path(path).unlink()
        except OSError:
            pass


RESET_SEQ = '\033[0m'
COLOR_SEQ = '\033[1;%dm'

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)


class Log:
    """
    Logs a given string to output with colors
    :param log_string: the string that should be logged

    The string functions returns the strings that would be logged.

    The idea is to use this Log class only for the CLI configuration wizard,
    and for all other logging we use the normal python logging module
    """

    @staticmethod
    def info_str(log_string: str):
        return COLOR_SEQ % WHITE + log_string + RESET_SEQ

    @staticmethod
    def success_str(log_string: str):
        return COLOR_SEQ % GREEN + log_string + RESET_SEQ

    @staticmethod
    def green_str(log_string: str):
        return COLOR_SEQ % GREEN + log_string + RESET_SEQ

    @staticmethod
    def warning_str(log_string: str):
        return COLOR_SEQ % YELLOW + log_string + RESET_SEQ

    @staticmethod
    def yellow_str(log_string: str):
        return COLOR_SEQ % YELLOW + log_string + RESET_SEQ

    @staticmethod
    def error_str(log_string: str):
        return COLOR_SEQ % RED + log_string + RESET_SEQ

    @staticmethod
    def debug_str(log_string: str):
        return COLOR_SEQ % CYAN + log_string + RESET_SEQ

    @staticmethod
    def cyan_str(log_string: str):
        return COLOR_SEQ % CYAN + log_string + RESET_SEQ

    @staticmethod
    def blue_str(log_string: str):
        return COLOR_SEQ % BLUE + log_string + RESET_SEQ

    @staticmethod
    def magenta_str(log_string: str):
        return COLOR_SEQ % MAGENTA + log_string + RESET_SEQ

    @staticmethod
    def info(log_string: str):
        print(Log.info_str(log_string))

    @staticmethod
    def success(log_string: str):
        print(Log.success_str(log_string))

    @staticmethod
    def warning(log_string: str):
        print(Log.warning_str(log_string))

    @staticmethod
    def yellow(log_string: str):
        print(Log.yellow_str(log_string))

    @staticmethod
    def error(log_string: str):
        print(Log.error_str(log_string))

    @staticmethod
    def debug(log_string: str):
        print(Log.debug_str(log_string))

    @staticmethod
    def blue(log_string: str):
        print(Log.blue_str(log_string))

    @staticmethod
    def magenta(log_string: str):
        print(Log.magenta_str(log_string))

    @staticmethod
    def cyan(log_string: str):
        print(Log.cyan_str(log_string))


def recursive_urlencode(data):
    """URL-encode a multidimensional dictionary.
    @param data: the data to be encoded
    @returns: the url encoded data
    """

    def recursion(data, base=None):
        if base is None:
            base = []
        pairs = []

        for key, value in data.items():
            new_base = base + [key]
            if hasattr(value, 'values'):
                pairs += recursion(value, new_base)
            else:
                new_pair = None
                if len(new_base) > 1:
                    first = quote(new_base.pop(0))
                    rest = map(quote, new_base)
                    new_pair = f"{first}[{']['.join(rest)}]={quote(str(value))}"
                else:
                    new_pair = f'{quote(str(key))}={quote(str(value))}'
                pairs.append(new_pair)
        return pairs

    return '&'.join(recursion(data))
