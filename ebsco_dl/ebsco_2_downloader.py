import asyncio
import hashlib
import json
import logging
import os
import posixpath
import re
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import ParseResult, quote, unquote, urlparse, urlsplit, urlunsplit

import aiofiles
import aiohttp
import pypdf
import urllib3
from aiohttp.client_exceptions import ClientError, ClientResponseError
from lxml import etree
from requests.sessions import Session

from ebsco_dl.utils import Log
from ebsco_dl.utils import PathTools as PT
from ebsco_dl.utils import (
    SimpleCookieJar,
    SslHelper,
    check_verbose,
    convert_to_aiohttp_cookie_jar,
    format_bytes,
    parse_xml_string,
)


@dataclass
class EbscoBookInfo:
    parsed_url: ParseResult
    book_id: str
    user_id: str
    book_format: str
    base_webview: str = field(init=False, default=None)
    on_page_json: Dict = field(init=False, default=None)

    checkout_token: str = field(init=False, default=None)

    book_info_json: Dict = field(init=False, default=None)
    pages_info_json: Dict = field(init=False, default=None)
    all_pages_ids: List = field(init=False, default=None)
    all_clean_pages_ids: List = field(init=False, default=None)


class ContentRangeError(ConnectionError):
    pass


class Ebsco2Downloader:
    stdHeader = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
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
        # logging.getLogger("requests").setLevel(logging.DEBUG)
        # logging.getLogger("urllib3").setLevel(logging.DEBUG)

        urllib3.disable_warnings()

        # init cookies
        cookies_path = 'cookies.txt'
        self.cookie_jar = SimpleCookieJar(cookies_path)
        if os.path.isfile(cookies_path):
            self.cookie_jar.load(ignore_discard=True, ignore_expires=True)

        self.session = self.create_session()

        # Parse download URL
        parsed_url = urlparse(self.download_url)

        # Check if it is a valid URL
        if not (parsed_url.path.startswith("/c/") and "/ebook-viewer/" in parsed_url.path):
            raise NotImplementedError('This type of URL is yet not supported')

        url_path_parts = parsed_url.path.split('/')
        self.book_info = EbscoBookInfo(
            parsed_url=parsed_url,
            user_id=url_path_parts[2],
            book_format=url_path_parts[4],
            book_id=url_path_parts[5],
        )

    @staticmethod
    def prettify_xml(xml_string):
        return etree.tostring(
            parse_xml_string(xml_string), pretty_print=True, encoding='utf-8', xml_declaration=True
        ).decode()

    def run(self):
        self.book_info.base_webview = self.get_url_view(self.download_url)
        self.book_info.on_page_json = json.loads(
            self.first_match(
                r'<script\s*id="__NEXT_DATA__"\s*type="application/json">({.*})\s*</script>',
                self.book_info.base_webview,
                'On page json',
            )
        )

        if self.book_info.book_id != self.book_info.on_page_json['query']['recordId']:
            print(
                f"Warning recordId is not equal: {self.book_info.book_id} != {self.book_info.on_page_json['query']['recordId']}"
            )

        self.book_info.book_info_json = self.load_book_info()
        self.book_info.pages_info_json = self.load_pages_info()

        self.book_info.all_pages_ids, self.book_info.all_clean_pages_ids = self.extract_artifact_ids(
            self.book_info.pages_info_json.get('pages', [])
        )

        self.book_info.turn_json = self.load_page_turn()
        self.book_info.checkout_token = self.book_info.turn_json['checkoutToken']

        if self.book_info.book_format == 'epub':
            asyncio.run(self.download_epub())
        elif self.book_info.book_format == 'pdf':
            self.download_pdf()
        else:
            raise NotImplementedError("This book format is not yet supported")

    def get_url_view(self, url: str):
        Log.info(f'Loading: `{url}`')

        response = self.session_get(url)

        if not response.ok:
            raise RuntimeError(f'Your session is broken! {response.reason}')

        if not urlparse(response.url).path.startswith(urlparse(url).path):
            raise RuntimeError('Your cookies or the session id in the URL are invalid!')

        return response.text

    def session_get(self, url):
        response = self.session.get(
            url,
            headers=self.stdHeader.copy(),
            verify=not self.skip_cert_verify,
            allow_redirects=True,
            timeout=60,
        )
        return response

    def get_cookie_jar(self) -> aiohttp.CookieJar:
        return convert_to_aiohttp_cookie_jar(self.cookie_jar)

    def create_session(self) -> Session:
        session = SslHelper.custom_requests_session(self.skip_cert_verify, True, True)
        session.cookies = self.cookie_jar
        return session

    @staticmethod
    def first_match(regex_with_group, text, pattern_name, default=None) -> str:
        found_match = re.search(regex_with_group, text)
        if found_match is None:
            if default is None:
                raise ValueError(f'Could not find {pattern_name}.')
            else:
                return default
        return found_match.group(1)

    def load_book_info(self):
        book_info_url = self.book_info.parsed_url._replace(
            path=f"/api/books/viewer/v1/c/{self.book_info.user_id}/record/{self.book_info.book_id}/format/{self.book_info.book_format}",
            query=None,
        ).geturl()

        Log.info(f"Loading book info: `{book_info_url}`")
        book_response = self.session_get(book_info_url)
        return json.loads(book_response.text)

    def load_pages_info(self):
        pages_info_url = self.book_info.parsed_url._replace(
            path=f"/api/books/toc/v1/c/{self.book_info.user_id}/record/{self.book_info.book_id}/format/{self.book_info.book_format}/toc",
            query=None,
        ).geturl()

        Log.info(f"Loading pages info: `{pages_info_url}`")
        pages_response = self.session_get(pages_info_url)
        return json.loads(pages_response.text)

    @staticmethod
    def extract_artifact_ids(artifact_list: List):
        all_pages_ids = []
        all_clean_pages_ids = []
        for page in artifact_list:
            # artifact IDs
            page_artifact_id = page.get('artifactId')
            page_artifact_id = page_artifact_id.split('#')[0]
            if page_artifact_id not in all_pages_ids and page_artifact_id != 'previewlimit':
                all_pages_ids.append(page_artifact_id)

            # clean IDs
            page_clean_id = page.get('id')
            if page_clean_id not in all_clean_pages_ids and page_clean_id != 'previewlimit':
                all_clean_pages_ids.append(page_clean_id)
        return all_pages_ids, all_clean_pages_ids

    def load_page_turn(self):
        turn_data = {
            "RetrievalDatabase": self.book_info.book_info_json.get("db"),
            "PageIds": self.book_info.all_clean_pages_ids[:1],
            # "PatronRequestedPageLabel": "265",
        }
        turn_url = self.book_info.parsed_url._replace(
            path=f"/api/books/viewer/v1/book/{self.book_info.book_info_json.get('bookId')}/format/{self.book_info.book_format}/page-turn",
            query=None,
        ).geturl()

        Log.info(f"Loading turn: `{turn_url}`")
        headers = self.stdHeader.copy()
        headers["Content-Type"] = "application/json"
        turn_response = self.session.post(
            turn_url,
            data=json.dumps(turn_data),
            headers=headers,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )
        return json.loads(turn_response.text)

    def download_pdf(self):
        # Extract Meta data
        book_title = self.book_info.book_info_json.get('bookTitle', 'untitled')

        # Start downloading Artifacts
        book_path = PT.path_of_book(self.storage_path, book_title)
        os.makedirs(str(book_path), exist_ok=True)
        pdf_content_files = asyncio.run(self.batch_download_pdf_parts(self.book_info.all_pages_ids, book_path))

        Log.info('Merging pdf artifacts to one pdf')
        merger = pypdf.PdfWriter()
        for idx, pdf_page in enumerate(pdf_content_files):
            merger.append(pdf_page)
            Log.info(f'Merged artifact {idx}')

        all_contents = self.book_info.pages_info_json.get('sections', [])
        for entry in all_contents:
            self.build_outline(merger, entry)

        Log.info('Writing PDF to disk (this can take long for big PDFs)')
        merger.write(str(book_path) + '.pdf')
        merger.close()

    async def get_can_continue_on_fail(self, url, session, old_headers, ssl_context):
        try:
            headers = old_headers.copy()
            headers['Range'] = 'bytes=0-4'
            resp = await session.request("GET", url, headers=headers, ssl=ssl_context)
            return resp.headers.get('Content-Range') is not None and resp.status == 206
        except Exception as err:
            if self.verbose:
                Log.debug(f"Failed to check if download can be continued on fail: {err}")
        return False

    async def batch_download_pdf_parts(self, dl_jobs: List[str], book_path: Path) -> List[Path]:
        """
        @param dl_jobs: List of rel_file_path
        @param is_essential: Applied to all jobs
        """
        semaphore = asyncio.Semaphore(self.max_parallel_dl)
        dl_results = await asyncio.gather(*[self.download_pdf_part(dl_job, book_path, semaphore) for dl_job in dl_jobs])
        for idx, dl_result in enumerate(dl_results):
            if not dl_result[0]:
                Log.error(f'Error: {dl_jobs[idx]} is essential. Abort! Please try again later!')
                exit(1)
        return [tup[1] for tup in dl_results]

    async def download_pdf_part(
        self,
        page_id: str,
        book_path: Path,
        semaphore: asyncio.Semaphore,
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ) -> Tuple[bool, Path]:
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
            headers = self.stdHeader.copy()

            dl_url = f'{self.book_info.on_page_json["runtimeConfig"]["BOOKS_CONTENT_EDGE_CLIENT_URL"]}/v1/artifact/{quote(page_id, safe='')}/{self.book_info.checkout_token}'

            if self.verbose:
                Log.info(f'Downloading {rel_file_path} from: {dl_url}')
            else:
                Log.info(f'Downloading {rel_file_path}...')

            received = 0
            tries_num = 0
            file_obj = None
            can_continue_on_fail = False
            finished_successfully = False
            ssl_context = SslHelper.get_ssl_context(self.skip_cert_verify, True, True)
            async with semaphore, aiohttp.ClientSession(
                cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
            ) as session:
                while tries_num < self.max_dl_retries:
                    try:
                        if tries_num > 0 and can_continue_on_fail:
                            headers["Range"] = f"bytes={received}-"
                        elif not can_continue_on_fail and 'Range' in headers:
                            del headers['Range']
                        async with session.request(
                            "GET", dl_url, headers=headers, raise_for_status=True, ssl=ssl_context
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
                            can_continue_on_fail = await self.get_can_continue_on_fail(
                                dl_url, session, headers, ssl_context
                            )
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
    def build_outline(merger, nav_dic, parent=None):
        new_parent = merger.add_outline_item(
            title=nav_dic.get('name'), page_number=nav_dic.get('startPageIndex'), parent=parent
        )
        child_contents = nav_dic.get('children', []) or []
        for entry in child_contents:
            Ebsco2Downloader.build_outline(merger, entry, new_parent)

    async def download_epub_page(
        self,
        semaphore: asyncio.Semaphore,
        artifact_url: str,
        artifact_file_path,
        page_file_path: str,
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ):
        ssl_context = SslHelper.get_ssl_context(self.skip_cert_verify, True, True)
        async with semaphore, aiohttp.ClientSession(
            cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
        ) as session:
            async with session.request(
                "GET", artifact_url, headers=self.stdHeader, raise_for_status=True, ssl=ssl_context
            ) as response:
                if not response.ok or unquote(str(response.url)) != unquote(artifact_url):
                    raise RuntimeError(f'We got rate limited! {response.reason}')

                if response.content_type == 'text/html':
                    response_text = await response.text()
                    if response_text.startswith('<script type="text/javascript">') and 'pageError' in response_text:
                        raise RuntimeError(f'Could not download {artifact_url}, epub is broken.')

                Log.info(f'Loaded artifact url: `{artifact_url}`')
                response_text = await response.text()

                split_xhtml = re.search(r'^(.*<body[^>]*>)(.*)(</body[^>]*>.*)$', response_text)
                xhtml_head, xhtml_body, _xhtml_footer = split_xhtml.groups()

                # Find Header includes
                artifact_includes = re.findall(r'src\s*=\s*"([^"]+)"', xhtml_head)
                artifact_includes += re.findall(r'href\s*=\s*"([^"]+)"', xhtml_head)
                # Find Body includes
                artifact_includes += re.findall(r'src\s*=\s*"([^"]+)"', xhtml_body)
                artifact_includes += re.findall(r'<image[^>]+href\s*=\s*"([^"]+)"', xhtml_body)

                async with aiofiles.open(artifact_file_path, 'w', encoding='utf-8') as fs:
                    await fs.write(response_text)

                Log.info(f'Written artifact: `{str(artifact_file_path)}`')

                result_artifact_includes = []
                # fix artifact_includes paths
                for artifact_include in artifact_includes:
                    # Ignore URLs, only download relative and absolute paths
                    if urlparse(artifact_include).scheme == '':
                        try:
                            own_directory = os.path.dirname(page_file_path)
                            correct_path = os.path.normpath(os.path.join(own_directory, artifact_include))
                        except BaseException:
                            correct_path = re.sub(r'^(\.\./)+', '', artifact_include)

                        result_artifact_includes.append(correct_path)
                    else:
                        logging.warning('Skipping external include: %s', artifact_include)

                return result_artifact_includes

    async def download_epub_include(
        self,
        semaphore: asyncio.Semaphore,
        artifact_url: str,
        artifact_url_path: str,
        artifact_file_path,
        all_css_includes: List[str],
        skipped_includes: List[str],
        conn_timeout: int = 10,
        read_timeout: int = 1800,
    ):
        ssl_context = SslHelper.get_ssl_context(self.skip_cert_verify, True, True)
        async with semaphore, aiohttp.ClientSession(
            cookie_jar=self.get_cookie_jar(), conn_timeout=conn_timeout, read_timeout=read_timeout
        ) as session:
            async with session.request(
                "GET", artifact_url, headers=self.stdHeader, raise_for_status=False, ssl=ssl_context
            ) as response:
                if not response.ok:
                    if artifact_url not in skipped_includes:
                        logging.error('Could not download %s, epub could be broken.', artifact_url)
                        skipped_includes.append(artifact_url)
                    return
                if unquote(str(response.url)) != unquote(artifact_url):
                    raise RuntimeError(f'We got rate limited! {response.reason}')

                Log.info(f'Loaded artifact url: `{artifact_url}`')

                if response.content_type == 'text/html':
                    response_text = await response.text()
                    if response_text.startswith('<script type="text/javascript">') and 'pageError' in response_text:
                        if artifact_url not in skipped_includes:
                            logging.error('Could not download %s, epub could be broken.', artifact_url)
                            skipped_includes.append(artifact_url)
                        return

                if artifact_url.lower().endswith('.css'):
                    response_text = await response.text()
                    artifact_includes = re.findall(r'url\s*\(["\']?([^"\')]+)["\']?\)', response_text)
                    for artifact_include in artifact_includes:
                        real_artifact_include = artifact_include

                        if artifact_include.startswith(('http:', 'https:')):
                            # skip external includes
                            if artifact_include not in skipped_includes:
                                skipped_includes.append(artifact_include)
                                logging.warning('Skipping external include: %s', real_artifact_include)
                            continue

                        try:
                            own_directory = os.path.dirname(artifact_url_path)
                            correct_path = os.path.normpath(os.path.join(own_directory, artifact_include))
                        except BaseException:
                            correct_path = re.sub(r'^(\.\./)+', '', artifact_include)

                        if correct_path not in all_css_includes:
                            all_css_includes.append(correct_path)

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

    async def download_epub(self):
        # Extract Meta data
        book_title = self.book_info.book_info_json.get('bookTitle', 'untitled')
        authors = self.book_info.book_info_json.get('authors', ['anonymous'])
        if isinstance(authors, str):
            authors = authors.split(', ')
        publication_year = self.book_info.book_info_json.get('publicationYear', '1970')

        # Start downloading Artifacts
        book_directory = PT.path_of_book(self.storage_path, book_title)

        all_includes = []
        skipped_includes = []
        epub_content_files = []
        epub_include_files = []

        page_tasks = []
        semaphore_pages = asyncio.Semaphore(self.max_parallel_dl)

        for page_id in self.book_info.all_pages_ids:
            page_file_path = page_id
            artifact_file_path = book_directory / page_id
            os.makedirs(str(artifact_file_path.parent), exist_ok=True)
            epub_content_files.append(artifact_file_path)

            artifact_url = f'{self.book_info.on_page_json["runtimeConfig"]["BOOKS_CONTENT_EDGE_CLIENT_URL"]}/v1/artifact/{quote(page_id, safe='')}/{self.book_info.checkout_token}'

            page_tasks.append(
                self.download_epub_page(
                    semaphore_pages,
                    artifact_url,
                    artifact_file_path,
                    page_file_path,
                )
            )

        result = await asyncio.gather(*page_tasks)

        # Collect all artifacts
        for artifact_includes in result:
            for artifact_include in artifact_includes:
                if artifact_include not in all_includes:
                    all_includes.append(artifact_include)

        # Download includes (Images, Stylesheets, Fonts)
        base_artifact_url = f'{self.book_info.on_page_json["runtimeConfig"]["BOOKS_CONTENT_EDGE_CLIENT_URL"]}/v1/checkout/{self.book_info.checkout_token}/artifact/'

        while len(all_includes) > 0:
            all_css_includes = []
            include_tasks = []
            semaphore_includes = asyncio.Semaphore(self.max_parallel_dl)
            for artifact_url_path in all_includes:
                artifact_url = base_artifact_url + artifact_url_path

                artifact_url_parts = urlsplit(artifact_url)

                normalized_path = posixpath.normpath(artifact_url_parts.path)

                artifact_url = urlunsplit(
                    (
                        artifact_url_parts.scheme,
                        artifact_url_parts.netloc,
                        normalized_path,
                        artifact_url_parts.query,
                        artifact_url_parts.fragment,
                    )
                )

                artifact_file_path = book_directory / artifact_url_path
                os.makedirs(str(artifact_file_path.parent), exist_ok=True)

                epub_include_files.append(artifact_file_path)
                include_tasks.append(
                    self.download_epub_include(
                        semaphore_includes,
                        artifact_url,
                        artifact_url_path,
                        artifact_file_path,
                        all_css_includes,
                        skipped_includes,
                    )
                )

            await asyncio.gather(*include_tasks)
            all_includes = all_css_includes

        # session.cookies.save(ignore_discard=True, ignore_expires=True)

        # Compose E-Pub
        epub_path = str(book_directory) + '.epub'
        epub = zipfile.ZipFile(epub_path, 'w', zipfile.ZIP_DEFLATED)
        book_path_oebps = book_directory / 'OEBPS'

        # Mimetype
        epub.writestr("mimetype", "application/epub+zip", compress_type=zipfile.ZIP_STORED)

        container_xml = '''<?xml version="1.0" encoding="UTF-8"?>
        <container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
            <rootfiles>
                <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
        </rootfiles>
        </container>
        '''
        # META-INF/container.xml
        epub.writestr("META-INF/container.xml", self.prettify_xml(container_xml))

        # OEBPS/content.opf
        creators = ''
        for idx, author in enumerate(authors):
            creators += f'<dc:creator id="creator{idx}" opf:role="aut">{self.escape(author)}</dc:creator>'

        epub_manifest = ''
        epub_spine = ''

        # build spine and add all normal xhtml files to manifest
        for idx, epub_content_file in enumerate(epub_content_files):
            relative_oebps_path = Path(os.path.relpath(epub_content_file, book_path_oebps)).as_posix()
            relative_path = Path(os.path.relpath(epub_content_file, book_directory)).as_posix()

            epub_manifest += (
                f'<item id="html{idx + 1}" href="{relative_oebps_path}" media-type="application/xhtml+xml"/>\n'
            )
            epub_spine += f'<itemref idref="html{idx + 1}" />\n'
            epub.write(str(epub_content_file), relative_path)

        # Add all includes to manifest
        mimetype_dict = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'svg': 'image/svg+xml',
            'css': 'text/css',
            'xpgt': 'application/vnd.adobe-page-template+xml',
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
            relative_oebps_path = Path(os.path.relpath(epub_include_file, book_path_oebps)).as_posix()
            relative_path = Path(os.path.relpath(epub_include_file, book_directory)).as_posix()

            file_ext = str(epub_include_file).rsplit('.', maxsplit=1)[-1].lower()
            if file_ext not in mimetype_dict:
                Log.error(f'Error: {file_ext} was not found in mimetype_dict')
                return False
            media_type = mimetype_dict[file_ext]
            idx = 0
            file_type = 'unknown'
            if file_ext in ['css', 'xpgt']:
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

            epub_manifest += f'<item id="{file_type}{idx}" href="{relative_oebps_path}" media-type="{media_type}"/>\n'

            # Maybe add html files to index? I'm not sure if included html needs to be added
            # epub_spine += f'<itemref idref="html{file_type}{idx}" />'
            epub.write(str(epub_include_file), relative_path)

        epub_manifest += '<item href="toc.ncx" id="ncx" media-type="application/x-dtbncx+xml"/>'

        epub_uuid = str(uuid.UUID(hashlib.sha256(self.book_info.book_id.encode()).hexdigest()[:32]))
        # <dc:language>{self.escape(language)}</dc:language>
        content_tpl = f'''<?xml version='1.0' encoding='UTF-8'?>
<package version="2.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="id">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">
    <dc:title>{self.escape(book_title)}</dc:title>
    <dc:date>{self.escape(publication_year)}</dc:date>
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
        epub.writestr('OEBPS/content.opf', self.prettify_xml(content_tpl))

        # OEBPS/toc.ncx
        authors_display = " and ".join(authors) if len(authors) > 1 else authors[0]

        all_sections = self.book_info.pages_info_json.get('sections', [])
        for entry in all_sections:
            self.fix_paths_in_structure(entry)

        nav_points = '\n'.join(self.build_nav_points(entry) for entry in all_sections)

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
        epub.writestr('OEBPS/toc.ncx', self.prettify_xml(toc_tpl))

        epub.close()
        return None

    @staticmethod
    def fix_paths_in_structure(nav_dic) -> str:
        artifact_id = nav_dic.get('artifactId')
        split = artifact_id.split('/', 1)
        nav_dic['artifactId'] = split[0].replace("epub", "EPUB") + "/" + split[1]

        for entry in nav_dic.get('children', []) or []:
            Ebsco2Downloader.fix_paths_in_structure(entry)

    @staticmethod
    def build_nav_points(nav_dic) -> str:
        return f'''
        <navPoint id="{nav_dic.get('id')}">
            <navLabel>
                <text>{nav_dic.get('name')}</text>
            </navLabel>
            <content src="{os.path.relpath(nav_dic.get('artifactId'), "OEBPS")}"/>
            {"\n".join(Ebsco2Downloader.build_nav_points(entry) for entry in nav_dic.get('children', []) or [])}
        </navPoint>
        '''
