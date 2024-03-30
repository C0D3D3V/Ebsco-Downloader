import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import uuid
import zipfile
from dataclasses import dataclass, field
from http.cookiejar import MozillaCookieJar
from pathlib import Path
from typing import List
from urllib.parse import ParseResult, parse_qs, urlparse

import aiofiles
import aiohttp
import certifi  # pylint: disable=unused-import
import pypdf
import urllib3
from aiohttp.client_exceptions import ClientError, ClientResponseError
from Cryptodome.Cipher import AES
from requests.sessions import Session

from ebsco_dl.utils import Log
from ebsco_dl.utils import PathTools as PT
from ebsco_dl.utils import (
    SimpleCookieJar,
    SslHelper,
    check_verbose,
    convert_to_aiohttp_cookie_jar,
    format_bytes,
    recursive_urlencode,
)


@dataclass
class EbscoUrl:
    parsed_url: ParseResult
    book_id: str
    session_id: str
    book_format: str
    vid: str
    rid: str
    base_webview: str = field(init=False, default=None)


class ContentRangeError(ConnectionError):
    pass


class EbscoDownloader:
    stdHeader = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
        ),
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    def __init__(
        self,
        storage_path: str,
        download_url: str,
        skip_cert_verify: bool,
    ):
        self.storage_path = storage_path
        self.download_url = download_url
        self.skip_cert_verify = skip_cert_verify
        self.max_dl_retries = 10
        self.max_parallel_dl = 10
        self.verbose = check_verbose()

        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        urllib3.disable_warnings()

    @staticmethod
    def from_query(parsed_querry, parameter_name, default=None):
        result = parsed_querry.get(parameter_name, default)
        if result is None:
            raise ValueError(
                f'Parameter {parameter_name} is not in query string. Please check that you use a valid URL.'
            )

        if isinstance(result, list):
            if len(result) != 1:
                raise ValueError(
                    f'Parameter {parameter_name} in query string contains unexpected content.'
                    + ' Please check that you use a valid URL.'
                )
            return result[0]
        return result

    def run(self):
        # Parse download URL
        parsed_url = urlparse(self.download_url)

        # Check if it is a valid URL
        if not parsed_url.path.startswith("/ehost/ebookviewer/ebook"):
            raise NotImplementedError('This type of URL is yet not supported')

        parsed_query = parse_qs(parsed_url.query)

        book_id = parsed_url.path.split('/')[-1] if parsed_url.path.split('/')[-1] != 'ebook' else None

        ebsco_url = EbscoUrl(
            parsed_url=parsed_url,
            book_id=book_id,
            session_id=self.from_query(parsed_query, 'sid'),
            book_format=self.from_query(parsed_query, 'format'),
            vid=self.from_query(parsed_query, 'vid', '0'),
            rid=self.from_query(parsed_query, 'rid', '1'),
        )

        # In any case open book URL, to get cookies.
        session = self.create_session()
        ebsco_url.base_webview = self.get_base_view(ebsco_url, session)

        if ebsco_url.book_id is None:
            ebsco_url.book_id = self.get_book_id(ebsco_url.base_webview)

        if ebsco_url.book_format == 'EK':
            asyncio.run(self.download_epub(ebsco_url, session))
        elif ebsco_url.book_format == 'EB':
            self.download_pdf(ebsco_url, session)
        else:
            raise NotImplementedError("This book format is not yet supported")

    def get_cookie_jar(self) -> aiohttp.CookieJar:
        cookies_path = 'cookies.txt'
        cookie_jar = SimpleCookieJar(cookies_path)
        if os.path.isfile(cookies_path):
            cookie_jar.load(ignore_discard=True, ignore_expires=True)
        return convert_to_aiohttp_cookie_jar(cookie_jar)

    def create_session(self) -> Session:
        session = SslHelper.custom_requests_session(self.skip_cert_verify, True, True)

        cookies_path = 'cookies.txt'
        session.cookies = MozillaCookieJar(cookies_path)
        if os.path.isfile(cookies_path):
            session.cookies.load(ignore_discard=True, ignore_expires=True)

        return session

    def get_base_view(self, ebsco_url: EbscoUrl, session: Session):
        base_data = recursive_urlencode(
            {
                'sid': ebsco_url.session_id,
                'vid': ebsco_url.vid,
                'format': ebsco_url.book_format,
                'rid': ebsco_url.rid,
            }
        )
        base_url = (
            f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}{ebsco_url.parsed_url.path}?{base_data}'
        )

        Log.info(f'Loading base: `{base_url}`')
        response = session.get(
            base_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        if not response.ok:
            raise RuntimeError(f'Your session is broken! {response.reason}')

        if not urlparse(response.url).path.startswith('/ehost/ebookviewer/ebook'):
            raise RuntimeError('Your cookies or the session id in the URL are invalid!')

        return response.text

    @staticmethod
    def first_match(regex_with_group, text, pattern_name, default=None) -> str:
        found_match = re.search(regex_with_group, text)
        if found_match is None:
            if default is None:
                raise ValueError(f'Could not find {pattern_name}.')
            else:
                return default
        return found_match.group(1)

    @staticmethod
    def replace_equals_with_count(string):
        match = re.search(r'(=+)$', string)
        if match:
            count = len(match.group(1))
            return string[:-count] + str(count)
        else:
            return string + '0'

    def get_book_id(self, webview: str):
        db = self.first_match(r'"Db"\s*:\s*"([^"]+)"', webview, 'Db part of book-id')
        term = self.first_match(r'"Term"\s*:\s*"([^"]+)"', webview, 'Term part of book-id')
        tag = self.first_match(r'"Tag"\s*:\s*"([^"]+)"', webview, 'Tag part of book-id')
        book_id = base64.urlsafe_b64encode(f'{db}__{term}__{tag}'.encode('utf-8')).decode('utf-8')
        return self.replace_equals_with_count(book_id)

    def download_pdf(self, ebsco_url: EbscoUrl, session: Session):
        # Ground truth is version 18.842.0.1477 of EBSCO, I did not implement this on older versions

        # First we retrieve the book info json
        book_info_data = recursive_urlencode(
            {
                'sid': ebsco_url.session_id,
                'vid': ebsco_url.vid,
                'theFormat': ebsco_url.book_format,
            }
        )
        book_info_url = (
            f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}'
            + f'/ehost/ebookViewer/DigitalObject/{ebsco_url.book_id}?{book_info_data}'
        )

        Log.info(f'Loading book info: `{book_info_url}`')
        response = session.get(
            book_info_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        book_info_json = json.loads(response.text)
        # all_content_entries = book_info_json.get('contents', {}).get('lp_Cover', {})
        all_pages = book_info_json.get('pageData', [])
        all_pages_ids = []
        for page in all_pages:
            page_artifact_id = page.get('artifactId')
            page_artifact_id = page_artifact_id.split('#')[0]
            if page_artifact_id not in all_pages_ids:
                all_pages_ids.append(page_artifact_id)

        # Extract Meta data
        book_title = book_info_json.get('title', 'untitled')
        # authors = book_info_json.get('authors', 'anonymous')
        # if isinstance(authors, str):
        #     authors = authors.split(', ')
        # publicationYear = book_info_json.get('publicationYear', '1970')
        # language = self.first_match(r'"Language"\s*:\s*"([^"]+)"', ebsco_url.base_webview, 'Language of book', 'eng')

        # Start downloading Artifacts
        book_path = PT.path_of_book(self.storage_path, book_title)
        os.makedirs(str(book_path), exist_ok=True)
        pdf_content_files = asyncio.run(self.batch_download_pdf_parts(all_pages_ids, book_path, ebsco_url))

        Log.info('Merging pdf artifacts to one pdf')
        merger = pypdf.PdfMerger()
        for idx, pdf_page in enumerate(pdf_content_files):
            merger.append(pdf_page)
            Log.info(f'Merged artifact {idx}')

        all_contents = book_info_json.get('contents', {})
        for entry in all_contents:
            self.build_outline(merger, all_contents.get(entry, {}))

        Log.info('Writing PDF to disk (this can take long for big PDFs)')
        merger.write(str(book_path) + '.pdf')

    async def get_can_continue_on_fail(self, url, session):
        try:
            headers = self.stdHeader.copy()
            headers['Range'] = 'bytes=0-4'
            resp = await session.request("GET", url, headers=headers)
            return resp.headers.get('Content-Range') is not None and resp.status == 206
        except Exception as err:
            if self.verbose:
                Log.debug(f"Failed to check if download can be continued on fail: {err}")
        return False

    async def batch_download_pdf_parts(self, dl_jobs: List[str], book_path: Path, ebsco_url: EbscoUrl) -> List[Path]:
        """
        @param dl_jobs: List of rel_file_path
        @param is_essential: Applied to all jobs
        """
        semaphore = asyncio.Semaphore(self.max_parallel_dl)
        dl_results = await asyncio.gather(
            *[self.download_pdf_part_from_ebsco(dl_job, book_path, ebsco_url, semaphore) for dl_job in dl_jobs]
        )
        for idx, dl_result in enumerate(dl_results):
            if not dl_result[0]:
                Log.error(f'Error: {dl_jobs[idx]} is essential. Abort! Please try again later!')
                exit(1)
        return [tup[1] for tup in dl_results]

    async def download_pdf_part_from_ebsco(
        self,
        page_id: str,
        book_path: Path,
        ebsco_url: EbscoUrl,
        semaphore: asyncio.Semaphore,
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ) -> (bool, Path):
        """Returns True if the file was successfully downloaded or exists"""

        rel_file_path = page_id.rsplit('/', 1)[1]
        local_path_raw = book_path / rel_file_path
        local_path = str(local_path_raw)

        if os.path.exists(local_path):
            # Warning: We do not check if the file is complete
            Log.info(f'{rel_file_path} is already present')
            return True, local_path_raw
        else:
            PT.make_base_dir(local_path)
            dl_url = (
                f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}'
                + f'/ehost/ebookviewer/artifact/{ebsco_url.book_id}/{ebsco_url.book_format}'
                + f'/{ebsco_url.session_id}/0/{page_id}'
            )
            if self.verbose:
                Log.info(f'Downloading {rel_file_path} from: {dl_url}')
            else:
                Log.info(f'Downloading {rel_file_path}...')

            received = 0
            total = 0
            tries_num = 0
            file_obj = None
            can_continue_on_fail = False
            headers = self.stdHeader.copy()
            finished_successfully = False
            async with semaphore, aiohttp.ClientSession(
                cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
            ) as session:
                while tries_num < self.max_dl_retries:
                    try:
                        if tries_num > 0 and can_continue_on_fail:
                            headers["Range"] = f"bytes={received}-"
                        elif not can_continue_on_fail and 'Range' in headers:
                            del headers['Range']
                        ssl_param = False if self.skip_cert_verify else None
                        async with session.request(
                            "GET", dl_url, headers=headers, raise_for_status=True, ssl=ssl_param
                        ) as resp:
                            # Download the file.
                            total = int(resp.headers.get("Content-Length", 0))
                            content_range = resp.headers.get("Content-Range", "")  # Example: bytes 200-1000/67589

                            if resp.status not in [200, 206]:
                                if self.verbose:
                                    Log.debug(f"Warning {rel_file_path} got status {resp.status}")

                            if tries_num > 0 and can_continue_on_fail and not content_range and resp.status != 206:
                                raise ContentRangeError(
                                    f"Server did not response for {rel_file_path} with requested range data"
                                )
                            file_obj = file_obj or await aiofiles.open(local_path, "wb")
                            chunk = await resp.content.read(1024 * 10)
                            chunk_idx = 0
                            while chunk:
                                received += len(chunk)
                                if chunk_idx % 100 == 0:
                                    Log.info(f"{rel_file_path} got {format_bytes(received)} / {format_bytes(total)}")
                                await file_obj.write(chunk)
                                chunk = await resp.content.read(1024 * 10)
                                chunk_idx += 1

                        if self.verbose:
                            Log.success(f'Downloaded {rel_file_path} to: {local_path}')
                        else:
                            Log.success(f'Successfully downloaded {rel_file_path}')

                        finished_successfully = True
                        break

                    except (ClientError, OSError, ValueError, ContentRangeError) as err:
                        if tries_num == 0:
                            can_continue_on_fail = await self.get_can_continue_on_fail(dl_url, session)
                        if (not can_continue_on_fail and received > 0) or isinstance(err, ContentRangeError):
                            can_continue_on_fail = False
                            # Clean up failed file because we can not recover
                            if file_obj is not None:
                                await file_obj.close()
                                file_obj = None
                            if os.path.exists(local_path):
                                os.unlink(local_path)
                            received = 0

                        if isinstance(err, ClientResponseError):
                            if err.status in [408, 409, 429]:  # pylint: disable=no-member
                                # 408 (timeout) or 409 (conflict) and 429 (too many requests)
                                # Retry after 1 sec
                                await asyncio.sleep(1)
                            else:
                                Log.info(f'{rel_file_path} could not be downloaded: {err.status} {err.message}')
                                if self.verbose:
                                    Log.info(f'Error: {str(err)}')
                                break

                        if self.verbose:
                            Log.warning(
                                f'(Try {tries_num} of {self.max_dl_retries})'
                                + f' Unable to download "{rel_file_path}": {str(err)}'
                            )
                        tries_num += 1

            if file_obj is not None:
                await file_obj.close()
            if not finished_successfully:
                if os.path.exists(local_path):
                    os.unlink(local_path)
                return False, local_path_raw
            return True, local_path_raw

    @staticmethod
    def build_outline(merger, nav_dic, parent=None) -> str:
        new_parent = merger.add_outline_item(
            title=nav_dic.get('title'), page_number=nav_dic.get('pages')[0], parent=parent
        )
        child_contents = nav_dic.get('childContents', {})
        for entry in child_contents:
            EbscoDownloader.build_outline(merger, child_contents.get(entry, {}), new_parent)

    @staticmethod
    def decrypt(data_base64, key_base64, iv_base_64):
        data = base64.b64decode(data_base64.encode('utf-8'))
        key = base64.b64decode(key_base64.encode('utf-8'))
        iv = base64.b64decode(iv_base_64.encode('utf-8'))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = cipher.decrypt(data)
        padding_bytes = decrypted_data[-1]
        if padding_bytes >= 1 and padding_bytes <= 16:
            return decrypted_data[:-padding_bytes].decode('utf-8')
        else:
            return decrypted_data.decode('utf-8')

    @staticmethod
    def old_decrypt(input_base64, key_base64):
        # Older version used GCM with the IV being part of the input (first 12 bytes)
        # last 16 bytes were the tag
        input_bytes = base64.b64decode(input_base64.encode('ascii'))
        iv = input_bytes[:12]
        data = input_bytes[12:-16]
        tag = input_bytes[-16:]
        key_bytes = base64.b64decode(key_base64.encode('ascii'))
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv)
        decrypted_data = cipher.decrypt(data)

        try:
            cipher.verify(tag)
        except ValueError as tag_error:
            print(f'ERROR: Tag does not match! {tag_error}')
            return None

        return decrypted_data.decode('utf-8')

    async def download_epub_page(
        self,
        semaphore: asyncio.Semaphore,
        artifact_url: str,
        artifact_file_path,
        page_id: str,
        book_key: str,
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ):
        async with semaphore, aiohttp.ClientSession(
            cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
        ) as session:
            ssl_param = False if self.skip_cert_verify else None
            async with session.request(
                "GET", artifact_url, headers=self.stdHeader, raise_for_status=True, ssl=ssl_param
            ) as response:
                if not response.ok or str(response.url) != artifact_url:
                    raise RuntimeError(f'We cot rate limited! {response.reason}')

                Log.info(f'Loaded artifact url: `{artifact_url}`')
                response_text = await response.text()

                xhtml_head = self.first_match(
                    r'([\s\S]*?)<script id=\'content-body\'', response_text, f'{page_id} artifact xhtml head'
                )
                encrypted_content = self.first_match(
                    r'<script id=\'content-body\'[^>]+>([^<]+)</script>', response_text, f'{page_id} artifact content'
                )
                xhtml_footer = '\r\n</body> </html>'
                decrypted = self.decrypt(encrypted_content[:-24], book_key, encrypted_content[-24:])

                # Find Header includes
                artifact_includes = re.findall(r'src\s*=\s*"([^"]+)"', xhtml_head)
                artifact_includes += re.findall(r'href\s*=\s*"([^"]+)"', xhtml_head)
                # Find Body includes
                artifact_includes += re.findall(r'src\s*=\s*"([^"]+)"', decrypted)

                async with aiofiles.open(artifact_file_path, 'w', encoding='utf-8') as fs:
                    await fs.write(xhtml_head)
                    await fs.write(decrypted)
                    await fs.write(xhtml_footer)

                Log.info(f'Written artifact: `{str(artifact_file_path)}`')
                return artifact_includes

    async def download_epub_include(
        self,
        semaphore: asyncio.Semaphore,
        artifact_url: str,
        artifact_file_path,
        all_css_includes: List[str],
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ):
        async with semaphore, aiohttp.ClientSession(
            cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
        ) as session:
            ssl_param = False if self.skip_cert_verify else None
            async with session.request(
                "GET", artifact_url, headers=self.stdHeader, raise_for_status=True, ssl=ssl_param
            ) as response:
                if not response.ok or str(response.url) != artifact_url:
                    raise RuntimeError(f'We cot rate limited! {response.reason}')

                Log.info(f'Loaded artifact url: `{artifact_url}`')

                if artifact_url.endswith('.css'):
                    response_text = await response.text()
                    artifact_includes = re.findall(r'url\s*\("?([^")]+)"?\)', response_text)
                    for artifact_include in artifact_includes:
                        artifact_include = re.sub(r'^(\.\./)+', '', artifact_include)
                        if artifact_include not in all_css_includes:
                            all_css_includes.append(artifact_include)

                async with aiofiles.open(artifact_file_path, 'wb') as fs:
                    await fs.write(await response.read())
                Log.info(f'Written artifact: `{str(artifact_file_path)}`')

    @staticmethod
    def escape(str_xml: str):
        str_xml = str_xml.replace("&", "&amp;")
        str_xml = str_xml.replace("<", "&lt;")
        str_xml = str_xml.replace(">", "&gt;")
        str_xml = str_xml.replace("\"", "&quot;")
        str_xml = str_xml.replace("'", "&apos;")
        return str_xml

    async def download_epub(self, ebsco_url: EbscoUrl, session: Session):
        # Ground truth is version 18.842.0.1477 of EBSCO, for older EBSCO version use older versions of ebsco-dl
        # https://github.com/C0D3D3V/Ebsco-Downloader/tree/5ce8f159975b9e544bc8d425f96b16591a2b057e

        # First we retrieve the book info json
        book_info_data = recursive_urlencode(
            {
                'sid': ebsco_url.session_id,
                'vid': ebsco_url.vid,
                'theFormat': ebsco_url.book_format,
            }
        )
        book_info_url = (
            f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}'
            + f'/ehost/ebookViewer/DigitalObject/{ebsco_url.book_id}?{book_info_data}'
        )

        Log.info(f'Loading book info: `{book_info_url}`')
        response = session.get(
            book_info_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        book_info_json = json.loads(response.text)
        all_pages = book_info_json.get('fileData', [])

        # Extract Meta data
        all_pages_ids = [page.get('artifactId') for page in all_pages]
        book_title = book_info_json.get('title', 'untitled')
        authors = book_info_json.get('authors', 'anonymous')
        if isinstance(authors, str):
            authors = authors.split(', ')
        publication_year = book_info_json.get('publicationYear', '1970')
        language = self.first_match(r'"Language"\s*:\s*"([^"]+)"', ebsco_url.base_webview, 'Language of book', 'en')

        # Collect encryption keys
        book_bsk = self.first_match(
            r'"Bsk"\s*:\s*"([^"]+)"', ebsco_url.base_webview, 'Book Session Key'
        )  # Book Session Key
        book_ek = book_info_json.get('ek')  # Encrypted Encryption Key
        book_sei = book_info_json.get('sei')  # IV for Encrypted Encryption Key
        # For the book content itself the IV is the last 24 Bytes

        book_key = self.decrypt(book_ek, book_bsk, book_sei)

        # Start downloading Artifacts
        book_directory = PT.path_of_book(self.storage_path, book_title)
        book_path_oebps = book_directory / 'OEBPS'
        os.makedirs(str(book_path_oebps), exist_ok=True)

        all_includes = []
        epub_content_files = []
        epub_include_files = []

        page_tasks = []
        semaphore_pages = asyncio.Semaphore(self.max_parallel_dl)
        for page_id in all_pages_ids:
            page_filename = '/'.join(page_id.split('/')[4:])
            artifact_file_path = book_path_oebps / page_filename
            os.makedirs(str(artifact_file_path.parent), exist_ok=True)
            epub_content_files.append(artifact_file_path)

            artifact_url = (
                f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}'
                + f'/ehost/ebookviewer/artifact/{ebsco_url.book_id}/{ebsco_url.book_format}'
                + f'/{ebsco_url.session_id}/0/{page_id}'
            )
            page_tasks.append(
                self.download_epub_page(semaphore_pages, artifact_url, artifact_file_path, page_id, book_key)
            )

        result = await asyncio.gather(*page_tasks)

        for artifact_includes in result:
            for artifact_include in artifact_includes:
                artifact_include = re.sub(r'^(\.\./)+', '', artifact_include)
                if artifact_include not in all_includes:
                    all_includes.append(artifact_include)

        # Download includes (Images, Stylesheets, Fonts)
        base_artifact = all_pages_ids[0]
        base_artifact_path = '/'.join(base_artifact.split('/')[:4]) + '/'

        base_artifact_url = (
            f'{ebsco_url.parsed_url.scheme}://{ebsco_url.parsed_url.hostname}'
            + f'/ehost/ebookviewer/artifact/{ebsco_url.book_id}/{ebsco_url.book_format}'
            + f'/{ebsco_url.session_id}/0/{base_artifact_path}'
        )

        while len(all_includes) > 0:
            all_css_includes = []
            include_tasks = []
            semaphore_includes = asyncio.Semaphore(self.max_parallel_dl)
            for include in all_includes:
                artifact_url = base_artifact_url + include

                artifact_file_path = book_path_oebps / include
                os.makedirs(str(artifact_file_path.parent), exist_ok=True)

                epub_include_files.append(artifact_file_path)
                include_tasks.append(
                    self.download_epub_include(semaphore_includes, artifact_url, artifact_file_path, all_css_includes)
                )

            await asyncio.gather(*include_tasks)
            all_includes = all_css_includes

        # session.cookies.save(ignore_discard=True, ignore_expires=True)

        # Compose E-Pub
        epub_path = str(book_directory) + '.epub'
        epub = zipfile.ZipFile(epub_path, 'w')

        # Mimetype
        epub.writestr("mimetype", "application/epub+zip")

        # META-INF/container.xml
        epub.writestr(
            "META-INF/container.xml",
            '''<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles>
        <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
   </rootfiles>
</container>
''',
        )

        # OEBPS/content.opf
        creators = ''
        for idx, author in enumerate(authors):
            creators += f'<dc:creator id="creator{idx}" opf:role="aut">{self.escape(author)}</dc:creator>'

        epub_manifest = ''
        epub_spine = ''

        # build spine and add all normal xhtml files to manifest
        for idx, epub_content_file in enumerate(epub_content_files):
            relative_path = str(epub_content_file.relative_to(book_path_oebps))

            epub_manifest += f'<item id="html{idx + 1}" href="{relative_path}" media-type="application/xhtml+xml"/>\n'
            epub_spine += f'<itemref idref="html{idx + 1}" />\n'
            epub.write(str(epub_content_file), 'OEBPS/' + relative_path)

        # Add all includes to manifest
        mimetype_dict = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'css': 'text/css',
            'xhtml': 'application/xhtml+xml',
            'otf': 'application/x-font-opentype',
            'ttf': 'application/x-font-ttf',
            'woff': 'font/woff',
            'woff2': 'font/woff2',
        }

        stylesheet_counter = 0
        image_counter = 0
        fonts_counter = 0
        html_counter = len(epub_content_files)
        for epub_include_file in epub_include_files:
            relative_path = str(epub_include_file.relative_to(book_path_oebps))

            file_ext = str(epub_include_file).rsplit('.', maxsplit=1)[-1]
            if file_ext not in mimetype_dict:
                Log.error(f'Error: {file_ext} was not found in mimetype_dict')
                return False
            media_type = mimetype_dict[file_ext]
            idx = 0
            file_type = 'unknown'
            if file_ext == 'css':
                file_type = 'stylesheet'
                stylesheet_counter += 1
                idx = stylesheet_counter
            elif file_ext in ['png', 'jpg', 'jpeg', 'gif', 'svg']:
                file_type = 'image'
                image_counter += 1
                idx = image_counter
            elif file_ext == 'xhtml':
                file_type = 'html'
                html_counter += 1
                idx = html_counter
                print('Warning! Found unexpected HTML!')
            elif file_ext in ['otf', 'ttf', 'woff', 'woff2']:
                file_type = 'fonts'
                fonts_counter += 1
                idx = fonts_counter

            epub_manifest += f'<item id="{file_type}{idx}" href="{relative_path}" media-type="{media_type}"/>\n'

            # Maybe add html files to index? I'm not sure if included html needs to be added
            # epub_spine += f'<itemref idref="html{file_type}{idx}" />'
            epub.write(str(epub_include_file), 'OEBPS/' + relative_path)

        epub_manifest += '<item href="toc.ncx" id="ncx" media-type="application/x-dtbncx+xml"/>'

        epub_uuid = str(uuid.UUID(hashlib.sha256(ebsco_url.book_id.encode()).hexdigest()[:32]))
        content_tpl = f'''<?xml version='1.0' encoding='UTF-8'?>
<package version="2.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="id">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">
    <dc:title>{self.escape(book_title)}</dc:title>
    <dc:date>{self.escape(publication_year)}</dc:date>
    <dc:language>{self.escape(language)}</dc:language>
    <dc:identifier
        id="id"
        opf:scheme="uuid">{epub_uuid}</dc:identifier>
    {creators}
    </metadata>
    <manifest>
        {epub_manifest}
    </manifest>
    <spine toc="ncx">
        {epub_spine}
    </spine>
</package>
'''
        epub.writestr('OEBPS/content.opf', content_tpl)

        # OEBPS/toc.ncx
        authors_display = " and ".join(authors) if len(authors) > 1 else authors[0]

        all_contents = book_info_json.get('contents', {})
        nav_points = '\n'.join(self.build_nav_points(all_contents.get(entry, {})) for entry in all_contents)

        toc_tpl = f'''<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1" xml:lang="en-US">
    <head>
        <meta name="dtb:totalPageCount" content="0"/>
    </head>
    <docTitle>
        <text>{book_title}</text>
    </docTitle>
    <docAuthor>
        <text>{authors_display}</text>
    </docAuthor>
    <navMap>
    {nav_points}
    </navMap>
</ncx>
'''
        epub.writestr('OEBPS/toc.ncx', toc_tpl)

        epub.close()

    @staticmethod
    def build_nav_points(nav_dic) -> str:
        return f'''
        <navPoint id="{nav_dic.get('id')}">
            <navLabel>
                <text>{nav_dic.get('title')}</text>
            </navLabel>
            <content src="{'/'.join(nav_dic.get('artifactId').split('/')[4:])}"/>
        </navPoint>
        ''' + '\n'.join(
            EbscoDownloader.build_nav_points(nav_dic.get('childContents', {}).get(entry, {}))
            for entry in nav_dic.get('childContents', {})
        )
