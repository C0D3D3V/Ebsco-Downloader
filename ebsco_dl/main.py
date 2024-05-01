#!/usr/bin/env python3
# coding=utf-8

import argparse
import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler

import colorlog
from colorama import just_fix_windows_console

from ebsco_dl.ebsco_downloader import EbscoDownloader
from ebsco_dl.utils import Log, ProcessLock, check_debug, check_verbose
from ebsco_dl.version import __version__


class ReRaiseOnError(logging.StreamHandler):
    """
    A logging-handler class which allows the exception-catcher of i.e. PyCharm
    to intervine
    """

    def emit(self, record):
        if hasattr(record, 'exception'):
            raise record.exception


def setup_logger(storage_path: str, verbose=False):
    log_formatter = logging.Formatter('%(asctime)s  %(levelname)s  {%(module)s}  %(message)s', '%Y-%m-%d %H:%M:%S')
    log_file = os.path.join(storage_path, 'EbscoDownloader.log')
    log_handler = RotatingFileHandler(
        log_file, mode='a', maxBytes=1 * 1024 * 1024, backupCount=2, encoding='utf-8', delay=0
    )
    stdout_log_handler = colorlog.StreamHandler()
    if sys.stdout.isatty() and not verbose:
        stdout_log_handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(asctime)s %(message)s', '%H:%M:%S'))
    else:
        stdout_log_handler.setFormatter(
            colorlog.ColoredFormatter(
                '%(log_color)s%(asctime)s  %(levelname)s  {%(module)s}  %(message)s', '%Y-%m-%d %H:%M:%S'
            )
        )

    log_handler.setFormatter(log_formatter)
    if verbose:
        log_handler.setLevel(logging.DEBUG)
        stdout_log_handler.setLevel(logging.DEBUG)
    else:
        log_handler.setLevel(logging.INFO)
        stdout_log_handler.setLevel(logging.DEBUG)

    app_log = logging.getLogger()
    if verbose:
        app_log.setLevel(logging.DEBUG)
    else:
        app_log.setLevel(logging.INFO)
    app_log.addHandler(log_handler)
    app_log.addHandler(stdout_log_handler)

    logging.info('--- ebsco-dl started ---------------------')
    Log.info('Ebsco Downloader starting...')
    if verbose:
        logging.debug('ebsco-dl version: %s', __version__)
        logging.debug('python version: %s', ".".join(map(str, sys.version_info[:3])))

    if check_debug():
        logging.info('Debug-Mode detected. Errors will be re-risen.')
        app_log.addHandler(ReRaiseOnError())


def _dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'"{str(path)}" is not a valid path. Make sure the directory exists.')


def _is_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url
    else:
        raise argparse.ArgumentTypeError(f'"{str(url)}" is not a valid url. Make sure the url starts with https://')


def _max_path_length_workaround(path):
    # Working around MAX_PATH limitation on Windows (see
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx)
    if os.name == 'nt':
        absfilepath = os.path.abspath(path)
        path = '\\\\?\\' + absfilepath
        Log.debug("Using absolute paths")
    else:
        Log.info("You are not on Windows, you don't need to use this workaround")
    return path


def get_parser():
    """
    Creates a new argument parser.
    """

    parser = argparse.ArgumentParser(description=('Ebsco Downloader - A collection of tools to download ebooks'))

    parser.add_argument(
        '--version', action='version', version='ebsco-dl ' + __version__, help='Print program version and exit'
    )

    parser.add_argument(
        'url',
        nargs=1,
        type=_is_url,
        help=('URL of the book that should be downloaded'),
    )

    parser.add_argument(
        '-p',
        '--path',
        default='.',
        type=_dir_path,
        help=(
            'Sets the location of the downloaded files. PATH must be an'
            + ' existing directory in which you have read and'
            + ' write access. (default: current working'
            + ' directory)'
        ),
    )

    parser.add_argument(
        '-mplw',
        '--max-path-length-workaround',
        default=False,
        action='store_true',
        help=(
            'If this flag is set, all path are made absolute '
            + 'in order to workaround the max_path limitation on Windows.'
            + 'To use relative paths on Windows you should disable the max_path limitation'
            + 'https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation'
        ),
    )

    parser.add_argument(
        '-scv',
        '--skip-cert-verify',
        default=False,
        action='store_true',
        help='If this flag is set, the SSL certificate '
        + 'is not verified. This option should only be used in '
        + 'non production environments.',
    )

    parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action='store_true',
        help='Print various debugging information',
    )

    return parser


# --- called at the program invocation: -------------------------------------
def main(args=None):
    """The main routine."""

    just_fix_windows_console()
    check_debug()

    parser = get_parser()
    args = parser.parse_args(args)
    if args.max_path_length_workaround:
        storage_path = _max_path_length_workaround(args.path)
    else:
        storage_path = args.path
    setup_logger(storage_path, args.verbose)
    skip_cert_verify = args.skip_cert_verify

    try:
        if not check_debug():
            ProcessLock.lock(storage_path)

        EbscoDownloader(storage_path, args.url[0], skip_cert_verify).run()

        Log.success('All done. Exiting..')
        ProcessLock.unlock(storage_path)
    except BaseException as e:
        print('\n')
        if not isinstance(e, ProcessLock.LockError):
            ProcessLock.unlock(storage_path)

        error_formatted = traceback.format_exc()
        logging.error(error_formatted, extra={'exception': e})

        if check_verbose() or check_debug():
            Log.cyan(f'{error_formatted}')
        else:
            Log.error(f'Exception: {e}')

        logging.debug('Exception-Handling completed. Exiting...')

        sys.exit(1)
