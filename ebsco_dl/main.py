#!/usr/bin/env python3
# coding=utf-8

import os
import sys
import logging
import argparse
import traceback

from logging.handlers import RotatingFileHandler

import ebsco_dl.utils.process_lock as process_lock

from ebsco_dl.utils.logger import Log
from ebsco_dl.version import __version__
from ebsco_dl.download_service.page_links_downloader import PageLinksDownloader

IS_DEBUG = False
IS_VERBOSE = False


class ReRaiseOnError(logging.StreamHandler):
    """
    A logging-handler class which allows the exception-catcher of i.e. PyCharm
    to intervine
    """

    def emit(self, record):
        if hasattr(record, 'exception'):
            raise record.exception


def run_download_pages(storage_path: str, download_url: str, skip_cert_verify: bool):
    Log.debug('Start downloading all Pages...')
    crawler = PageLinksDownloader(storage_path, download_url, skip_cert_verify)
    result = crawler.run()
    if result is None:
        Log.success('Downloading all Pages finished')


def setup_logger(storage_path: str, verbose=False):
    global IS_VERBOSE
    log_formatter = logging.Formatter('%(asctime)s  %(levelname)s  {%(module)s}  %(message)s', '%Y-%m-%d %H:%M:%S')
    log_file = os.path.join(storage_path, 'EbscoDownloader.log')
    log_handler = RotatingFileHandler(
        log_file, mode='a', maxBytes=1 * 1024 * 1024, backupCount=2, encoding='utf-8', delay=0
    )

    log_handler.setFormatter(log_formatter)
    if verbose:
        log_handler.setLevel(logging.DEBUG)
        IS_VERBOSE = True
    else:
        log_handler.setLevel(logging.INFO)

    app_log = logging.getLogger()
    if verbose:
        app_log.setLevel(logging.DEBUG)
    else:
        app_log.setLevel(logging.INFO)
    app_log.addHandler(log_handler)

    logging.info('--- ebsco-dl started ---------------------')
    Log.info('Ebsco Downloader starting...')
    if verbose:
        logging.debug('ebsco-dl version: %s', __version__)
        logging.debug('python version: %s', ".".join(map(str, sys.version_info[:3])))

    if IS_DEBUG:
        logging.info('Debug-Mode detected. Errors will be re-risen.')
        app_log.addHandler(ReRaiseOnError())


def _dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'"{str(path)}" is not a valid path. Make sure the directory exists.')


def _file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'"{str(path)}" is not a valid path. Make sure the file exists.')


def _is_url(url):
    if url.startswith('http://') or url.startswith('https://'):
        return url
    else:
        raise argparse.ArgumentTypeError(f'"{str(url)}" is not a valid url. Make sure the url starts with https://')


def check_debug():
    global IS_DEBUG
    if 'pydevd' in sys.modules:
        IS_DEBUG = True
        Log.debug('[RUNNING IN DEBUG-MODE!]')


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
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '--version', action='version', version='ebsco-dl ' + __version__, help='Print program version and exit'
    )

    group.add_argument(
        '-dp',
        '--download-pages',
        default=None,
        nargs=1,
        type=_is_url,
        help=('Downloads all pages from all catergories if not other defined'),
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
        if not IS_DEBUG:
            process_lock.lock(storage_path)

        if args.download_pages is not None and len(args.download_pages) == 1:
            run_download_pages(storage_path, args.download_pages[0], skip_cert_verify)

        Log.success('All done. Exiting..')
        process_lock.unlock(storage_path)
    except BaseException as e:
        print('\n')
        if not isinstance(e, process_lock.LockError):
            process_lock.unlock(storage_path)

        error_formatted = traceback.format_exc()
        logging.error(error_formatted, extra={'exception': e})

        if IS_VERBOSE or IS_DEBUG:
            Log.critical(f'{error_formatted}')
        else:
            Log.error(f'Exception: {e}')

        logging.debug('Exception-Handling completed. Exiting...')

        sys.exit(1)
