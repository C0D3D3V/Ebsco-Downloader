import os
import re
import json
import html
import base64
import logging
import zipfile

import urllib.parse

from http.cookiejar import MozillaCookieJar
from Cryptodome.Cipher import AES
from urllib.parse import urlparse, parse_qs

import certifi
import urllib3
import requests

from ebsco_dl.utils.logger import Log
from ebsco_dl.download_service.path_tools import PathTools


class PageLinksDownloader:
    stdHeader = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
            # 'Mozilla/5.0 (Linux; Android 7.1.1; Moto G Play Build/NPIS26.48-43-2; wv) AppleWebKit/537.36'
            #  + ' (KHTML, like Gecko) Version/4.0 Chrome/71.0.3578.99 Mobile Safari/537.36'
        ),
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    xml_ns = {'atom': 'http://www.w3.org/2005/Atom'}
    viewer_page_link_patern = re.compile(
        r'<iframe id="ViewerServiceFrame" title=Viewer name="accessibleViewport" src="(https://pdc-evs.ebscohost.com/EbscoViewerService/ebook[^"]+)"'
    )
    viewer_token_patern = re.compile(r'var\s+token\s*=\s*"([^"]+)";')
    book_session_key_pattern = re.compile(r'"bookSessionKey":\s*"([^"]+)",')
    searchTerm_pattern = re.compile(r'"searchTerm":\s*"([^"]+)",')
    isPLink_pattern = re.compile(r'"isPLink":\s*"([^"]+)",')
    page_splitter_pattern = re.compile(r'(.*<body[^>]*>)(.*)(<\/body[^>]*>.*)')
    src_pattern = re.compile(r'src\s*=\s*"([^"]+)"')
    href_pattern = re.compile(r'href\s*=\s*"([^"]+)"')
    style_src_pattern = re.compile(r'url\s*\(([^)]+)\)')
    style_src2_pattern = re.compile(r'url\s*\("([^"]+)"\)')

    def __init__(
        self,
        storage_path: str,
        download_url: str,
        skip_cert_verify: bool,
    ):
        self.storage_path = storage_path
        self.download_url = download_url
        self.skip_cert_verify = skip_cert_verify

        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        urllib3.disable_warnings()

    def run(self):

        # Parse download URL
        if not self.download_url.startswith('https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookviewer/ebook/'):
            Log.error(
                'Only URLs that starts with `https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookviewer/ebook/` are supported currently!'
            )
            return False

        parsed_url = urlparse(self.download_url)
        parsed_querry = parse_qs(parsed_url.query)

        book_id = parsed_url.path.split('/')[-1]

        session_id_array = parsed_querry.get('sid', [])
        if len(session_id_array) != 1:
            Log.error('Session ID not in paramter list!')
            return False
        format_array = parsed_querry.get('format', [])
        if len(format_array) != 1:
            Log.error('Format not in paramter list!')
            return False
        vid_array = parsed_querry.get('vid', ['0'])
        vid = vid_array[0]
        rid_array = parsed_querry.get('rid', ['1'])
        rid = rid_array[0]

        session_id = session_id_array[0]
        book_format = format_array[0]

        if book_format != 'EK':
            Log.error('Currently only EK format is supported (PDF will follow)')
            return False

        # Setup Session
        session = requests.Session()

        cookies_path = 'cookies.txt'
        session.cookies = MozillaCookieJar(cookies_path)
        if os.path.isfile(cookies_path):
            session.cookies.load(ignore_discard=True, ignore_expires=True)

        # Download Base URL
        base_data = self.recursive_urlencode(
            {
                'sid': session_id,
                'vid': vid,
                'format': book_format,
                'rid': rid,
            }
        )
        base_url = f'https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookviewer/ebook/{book_id}?{base_data}'

        print(f'Loading base url: `{base_url}`')
        response = session.get(
            base_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        if not response.ok:
            Log.error(f'Your session is broken! {response.reason}')
            return False

        if response.url.startswith('https://login.ukzn.idm.oclc.org'):
            Log.error('Your cookies are invalid!')
            return False

        # Extract Viewer URL
        viewer_page_link_result = self.viewer_page_link_patern.findall(response.text)

        if len(viewer_page_link_result) <= 0:
            Log.error('No viewer found, check book and session id!')
            return False
        elif len(viewer_page_link_result) != 1:
            Log.error('O.o more then one viewer found!')
            return False

        viewer_url = urllib.parse.unquote(html.unescape(viewer_page_link_result[0]))

        # Download Viewer URL
        print(f'Loading viwer url: `{viewer_url}`')
        response = session.get(
            viewer_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        if not response.ok:
            Log.error(f'Coukld not open viewer! {response.reason}')
            return False

        # Extract Viewer Parameters
        viewer_token_result = self.viewer_token_patern.findall(response.text)

        if len(viewer_token_result) <= 0:
            Log.error('No viewer token found!')
            return False
        elif len(viewer_token_result) != 1:
            Log.error('O.o more then one viewer token found!')
            return False

        book_session_key_result = self.book_session_key_pattern.findall(response.text)
        if len(book_session_key_result) <= 0:
            Log.error('No book session key found!')
            return False
        elif len(book_session_key_result) != 1:
            Log.error('O.o more then one book session key found!')
            return False

        searchTerm_result = self.searchTerm_pattern.findall(response.text)
        searchTerm = 'default'
        if len(searchTerm_result) >= 1:
            searchTerm = searchTerm_result[0]

        isPLink_result = self.isPLink_pattern.findall(response.text)
        isPLink = 'true'
        if len(isPLink_result) >= 1:
            isPLink = isPLink_result[0]

        viewer_token = viewer_token_result[0]
        book_session_key = book_session_key_result[0]

        # Download Book Info URL
        book_info_data = self.recursive_urlencode(
            {
                'sid': session_id,
                'vid': vid,
                'theFormat': book_format,
            }
        )
        book_info_url = (
            f'https://web-p-ebscohost-com.ukzn.idm.oclc.org/ehost/ebookViewer/DigitalObject/{book_id}?{book_info_data}'
        )

        print(f'Loading book info url: `{book_info_url}`')
        response = session.get(
            book_info_url,
            headers=self.stdHeader,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        # Extrat Book Infos
        book_info_json = json.loads(response.text)

        all_pages = book_info_json.get('pageData', [])

        all_pages_artifact_ids = []

        for page in all_pages:
            page_artifactId = page.get('artifactId', '')
            page_artifactId = page_artifactId.split('#')[0]
            if page_artifactId not in all_pages_artifact_ids:
                all_pages_artifact_ids.append(page_artifactId)

        book_title = book_info_json.get('title', 'untitled')
        authors = book_info_json.get('authors', ['anonymous'])
        publicationYear = book_info_json.get('publicationYear', 'unknown')

        info_an = book_info_json.get('an', None)
        # info_ek = book_info_json.get('ek', None)
        # info_sei = book_info_json.get('sei', None)
        info_doid = book_info_json.get('id', None)
        info_db = book_info_json.get('db', None)

        # for authentification use viewer_token (evsToken)
        # Authorization = "Basic viewer_token, Bearer "

        # Download Digital Object for Viewer
        viewer_headers = self.get_viewer_header(viewer_token)

        digital_obj_data = self.recursive_urlencode(
            {
                'db': info_db,
                'an': info_an,
                'doid': info_doid,
                'format': book_format,
                'language': 'en',
                'bookSessionKey': book_session_key,
                'isHoldModalEnabled': 'true',
                'isPLink': isPLink,
                'searchTerm': searchTerm,
            }
        )
        digital_obj_url = f'https://pdc-evs.ebscohost.com/EbscoViewerService/api/EbookDigitalObject?{digital_obj_data}'

        print(f'Loading digital obj url: `{digital_obj_url}`')
        response = session.get(
            digital_obj_url,
            headers=viewer_headers,
            verify=(not self.skip_cert_verify),
            allow_redirects=True,
            timeout=60,
        )

        # Extract Keys
        digital_obj_json = json.loads(response.text)

        # update viewer token using the new evsToken
        viewer_token_new = digital_obj_json.get('evsToken', viewer_token)
        viewer_headers = self.get_viewer_header(viewer_token_new)

        book_ek = digital_obj_json.get('ek', None)
        if book_ek is None:
            Log.error('No encryption key found!')
            return False

        book_key = self.decrypt(book_ek, book_session_key)

        # Start downloading Artifacts
        book_directory = PathTools.path_of_book(self.storage_path, book_title)
        book_path_OEBPS = book_directory / 'OEBPS'

        all_includes = []
        epub_content_files = []
        epub_include_files = []

        for artifact_id in all_pages_artifact_ids:
            artifact_id_split = artifact_id.split('/')
            subfolder = artifact_id_split[-2]
            artifact_filename = artifact_id_split[-1]
            artifact_file_path = str(book_path_OEBPS / subfolder / artifact_filename)
            epub_content_files.append(book_path_OEBPS / subfolder / artifact_filename)

            artifact_data = self.recursive_urlencode(
                {
                    'artifactId': artifact_id,
                    'db': info_db,
                    'an': info_doid,
                    'format': book_format,
                    'language': 'en',
                    'pageNumber': '-1',
                    'bookKey': book_key,
                    'pageCount': '1',
                }
            )
            artifact_url = f'https://pdc-evs.ebscohost.com/EbscoViewerService/api/EBookArtifact?{artifact_data}'

            # if os.path.exists(artifact_file_path):
            #     print(f'Skipping download of artifact url: `{artifact_url}`')
            #     continue

            print(f'Loading artifact url: `{artifact_url}`')
            response = session.get(
                artifact_url,
                headers=viewer_headers,
                verify=(not self.skip_cert_verify),
                allow_redirects=True,
                timeout=60,
            )

            # Compose xhtml
            html_splitted_result = self.page_splitter_pattern.findall(response.text)
            if len(html_splitted_result) <= 0:
                Log.error('HTML was not splitable!')
                return False
            elif len(html_splitted_result) != 1:
                Log.error('More then one HTML parts found in artifact!')
                return False

            html_splitted = html_splitted_result[0]

            decrypted = self.decrypt(html_splitted[1], book_key)

            # Find Header includes
            artifact_includes = self.src_pattern.findall(html_splitted[0])
            artifact_includes += self.href_pattern.findall(html_splitted[0])
            # Find Body includes
            artifact_includes += self.src_pattern.findall(decrypted)

            for artifact_include in artifact_includes:
                if artifact_include not in all_includes:
                    all_includes.append(artifact_include)

            # Save Artifact to disk
            if not os.path.exists(str(book_path_OEBPS / subfolder)):
                os.makedirs(str(book_path_OEBPS / subfolder))

            with open(artifact_file_path, 'w', encoding='utf-8') as fs:
                fs.write(html_splitted[0] + '\n')
                fs.write(decrypted + '\n')
                fs.write(html_splitted[2] + '\n')

        # Download includes (Images, Stylesheets, Fonts)
        base_artifact = all_pages_artifact_ids[0]
        base_artifact_path = base_artifact[: -len(base_artifact.split('/')[-1])]
        base_artifact_url = f'https://pdc-evs.ebscohost.com/EbscoViewerService/api/EBookArtifact/{book_format}/{info_an}/{session_id}/{base_artifact_path}'

        for include in all_includes:
            artifact_url = base_artifact_url + include

            include_split = include.split('/')
            subfolder = include_split[1]
            artifact_filename = include_split[2]
            artifact_file_path = str(book_path_OEBPS / subfolder / artifact_filename)
            epub_include_files.append(book_path_OEBPS / subfolder / artifact_filename)

            # if os.path.exists(artifact_file_path):
            #     print(f'Skipping download of artifact url: `{artifact_url}`')
            #     continue

            print(f'Loading artifact url: `{artifact_url}`')
            response = session.get(
                artifact_url,
                headers=self.stdHeader,
                verify=(not self.skip_cert_verify),
                allow_redirects=True,
                timeout=60,
            )
            if artifact_filename.endswith('css'):
                artifact_includes = self.style_src_pattern.findall(response.text)
                artifact_includes += self.style_src2_pattern.findall(response.text)
                for artifact_include in artifact_includes:
                    if artifact_include not in all_includes:
                        all_includes.append(artifact_include)

            if not os.path.exists(str(book_path_OEBPS / subfolder)):
                os.makedirs(str(book_path_OEBPS / subfolder))

            with open(artifact_file_path, 'wb') as fs:
                fs.write(response.content)

        # session.cookies.save(ignore_discard=True, ignore_expires=True)

        # Compose E-Pub
        epub_path = str(book_directory) + '.epub'
        epub = zipfile.ZipFile(epub_path, 'w')

        epub.writestr("mimetype", "application/epub+zip")

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

        creators = ''
        for author in authors:
            creators += f'<dc:creator opf:role="aut">{author}</dc:creator>'

        epub_manifest = ''
        epub_spine = ''

        # Write all files into epub
        for idx, epub_content_file in enumerate(epub_content_files):
            relativ_path = str(epub_content_file.relative_to(book_path_OEBPS))

            epub_manifest += f'<item id="html{idx + 1}" href="{relativ_path}" media-type="application/xhtml+xml"/>'
            epub_spine += f'<itemref idref="html{idx + 1}" />'
            epub.write(str(epub_content_file), 'OEBPS/' + relativ_path)

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
            relativ_path = str(epub_include_file.relative_to(book_path_OEBPS))

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

            epub_manifest += f'<item id="{file_type}{idx}" href="{relativ_path}" media-type="{media_type}"/>'

            # Maybe add html files to index?
            # epub_spine += f'<itemref idref="html{file_type}{idx}" />'
            epub.write(str(epub_include_file), 'OEBPS/' + relativ_path)

        index_tpl = f'''<?xml version="1.0"?>
<package version="2.0" xmlns="http://www.idpf.org/2007/opf">
    <metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">
    <dc:title>{book_title}</dc:title>
    <dc:date>{publicationYear}</dc:date>
    <dc:language>en</dc:language>
    {creators}
    <metadata/>
    <manifest>
        {epub_manifest}
    </manifest>
    <spine toc="ncx">
        {epub_spine}
    </spine>
</package>
'''
        epub.writestr('OEBPS/Content.opf', index_tpl)
        epub.close()

    def get_viewer_header(self, viewer_token_to_use):
        viewer_headers = self.stdHeader
        authorization_field = f"Basic {viewer_token_to_use}, Bearer "
        viewer_headers['Authorization'] = authorization_field
        return viewer_headers

    def decrypt(self, input_base64, key_base64):
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

    @staticmethod
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
                        first = urllib.parse.quote(new_base.pop(0))
                        rest = map(urllib.parse.quote, new_base)
                        new_pair = f"{first}[{']['.join(rest)}]={urllib.parse.quote(str(value))}"
                    else:
                        new_pair = f'{urllib.parse.quote(str(key))}={urllib.parse.quote(str(value))}'
                    pairs.append(new_pair)
            return pairs

        return '&'.join(recursion(data))
