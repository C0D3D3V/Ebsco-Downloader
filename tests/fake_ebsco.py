import asyncio
import io
import json
import threading
from typing import Dict, List, Union

import pypdf
from aiohttp import web

USER_ID = 'user1'
BOOK_ID = 'book1'
INTERNAL_BOOK_ID = 'internal-book-1'
CHECKOUT_TOKEN = 'checkout-token-1'
BOOK_TITLE = 'Game Theory: A Test'
SESSION_COOKIE = 'ezproxy'

XHTML_PAGE = '''<?xml version="1.0" encoding="utf-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title>{title}</title>
  <link href="../css/style.css" rel="stylesheet" type="text/css"/>
</head>
<BODY class="chapter">
  <h1>{title}</h1>
  <img src="../images/figure.png" alt=""/>
  <a href="other.xhtml">next</a>
</BODY>
</html>
'''

STYLESHEET = '''@font-face { font-family: "Book"; src: url("../fonts/book.woff"); }
@import url(style.css);
.chapter { background: url(../images/missing.png); }
'''

EPUB_INCLUDES = {
    'EPUB/css/style.css': STYLESHEET.encode(),
    'EPUB/images/figure.png': b'\x89PNG fake image',
    'EPUB/fonts/book.woff': b'wOFF fake font',
}

# A failure is 'hang' (no answer until the client gives up), 'cut' (connection drops after half of the body)
# or an HTTP status code.
Failure = Union[str, int]


def make_pdf(page_count: int) -> bytes:
    writer = pypdf.PdfWriter()
    for _ in range(page_count):
        writer.add_blank_page(width=100, height=100)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


class FakeEbsco:
    """Serves the subset of research.ebsco.com that Ebsco2Downloader talks to, on a local port."""

    def __init__(self, book_format: str):
        self.book_format = book_format
        self.require_cookie = True
        self.hang_seconds = 5
        self.failures: Dict[str, List[Failure]] = {}
        self.request_counts: Dict[str, int] = {}
        self.supports_ranges = False
        self.range_headers: Dict[str, List[str]] = {}
        self.book_info_override = None
        self.page_turn = {'checkoutToken': CHECKOUT_TOKEN}

        if book_format == 'epub':
            self.page_ids = ['EPUB/xhtml/ch1.xhtml', 'EPUB/xhtml/ch2.xhtml']
            self.artifacts = {
                page_id: XHTML_PAGE.format(title=f'Chapter {idx}').encode()
                for idx, page_id in enumerate(self.page_ids, start=1)
            }
            self.sections = [
                {
                    'id': 'sec1',
                    'name': 'Chapter 1',
                    'artifactId': 'epub/xhtml/ch1.xhtml',
                    'children': [{'id': 'sec2', 'name': 'Chapter 2', 'artifactId': 'epub/xhtml/ch2.xhtml'}],
                }
            ]
        else:
            self.page_ids = ['pdf/part1.pdf', 'pdf/part2.pdf', 'pdf/part3.pdf']
            self.artifacts = {page_id: make_pdf(page_count=2) for page_id in self.page_ids}
            self.sections = [
                {'id': 'sec1', 'name': 'Chapter 1', 'startPageIndex': 0, 'children': []},
                {
                    'id': 'sec2',
                    'name': 'Chapter 2',
                    'startPageIndex': 2,
                    'children': [{'id': 'sec3', 'name': 'Section 2.1', 'startPageIndex': 4}],
                },
            ]
        self.includes = dict(EPUB_INCLUDES)

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._runner = None
        self.base_url = None

    @property
    def viewer_url(self) -> str:
        return f'{self.base_url}/c/{USER_ID}/ebook-viewer/{self.book_format}/{BOOK_ID}'

    def start(self):
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._start_server(), self._loop).result()

    def stop(self):
        asyncio.run_coroutine_threadsafe(self._stop_server(), self._loop).result()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join()

    async def _stop_server(self):
        await self._runner.cleanup()
        handlers_still_running = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in handlers_still_running:
            task.cancel()
        await asyncio.gather(*handlers_still_running, return_exceptions=True)

    async def _start_server(self):
        app = web.Application()
        app.router.add_get('/c/{user}/ebook-viewer/{book_format}/{book}', self._viewer)
        app.router.add_get('/login', self._login)
        app.router.add_get('/api/books/viewer/v1/c/{user}/record/{book}/format/{book_format}', self._book_info)
        app.router.add_get('/api/books/toc/v1/c/{user}/record/{book}/format/{book_format}/toc', self._toc)
        app.router.add_post('/api/books/viewer/v1/book/{book}/format/{book_format}/page-turn', self._page_turn)
        app.router.add_get('/edge/v1/artifact/{page_id}/{token}', self._artifact)
        app.router.add_get('/edge/v1/checkout/{token}/artifact/{path:.*}', self._include)
        self._runner = web.AppRunner(app, shutdown_timeout=0.1)
        await self._runner.setup()
        site = web.TCPSite(self._runner, '127.0.0.1', 0)
        await site.start()
        port = self._runner.addresses[0][1]
        self.base_url = f'http://127.0.0.1:{port}'

    async def _respond(self, request, key: str, body: bytes, content_type: str):
        self.request_counts[key] = self.request_counts.get(key, 0) + 1
        range_header = request.headers.get('Range')
        if range_header:
            self.range_headers.setdefault(key, []).append(range_header)

        planned = self.failures.get(key)
        failure = planned.pop(0) if planned else None
        if failure == 'hang':
            await asyncio.sleep(self.hang_seconds)
            return web.Response(status=504)
        if isinstance(failure, int):
            return web.Response(status=failure)

        status = 200
        headers = {'Content-Type': content_type}
        if range_header and self.supports_ranges:
            start = int(range_header[len('bytes=') :].split('-')[0])
            headers['Content-Range'] = f'bytes {start}-{len(body) - 1}/{len(body)}'
            body = body[start:]
            status = 206

        if failure == 'cut':
            headers['Content-Length'] = str(len(body))
            response = web.StreamResponse(status=status, headers=headers)
            await response.prepare(request)
            await response.write(body[: len(body) // 2])
            request.transport.close()
            return response
        return web.Response(status=status, body=body, headers=headers)

    async def _viewer(self, request):
        if self.require_cookie and SESSION_COOKIE not in request.cookies:
            raise web.HTTPFound('/login?redirect_token=secret')
        next_data = {
            'query': {'recordId': BOOK_ID},
            'runtimeConfig': {'BOOKS_CONTENT_EDGE_CLIENT_URL': f'{self.base_url}/edge'},
        }
        html = (
            '<html><head></head><body><div id="__next"></div>'
            f'<script id="__NEXT_DATA__" type="application/json">{json.dumps(next_data)}</script>'
            '<script>window.__later = {"a": 1}</script></body></html>'
        )
        return web.Response(text=html, content_type='text/html')

    async def _login(self, request):
        return web.Response(text='<html>Please log in</html>', content_type='text/html')

    async def _book_info(self, request):
        if self.book_info_override is not None:
            return self.book_info_override
        return web.json_response(
            {
                'bookTitle': BOOK_TITLE,
                'authors': 'Ada Lovelace, Alan Turing',
                'publicationYear': '2026',
                'db': 'nlebk',
                'bookId': INTERNAL_BOOK_ID,
            }
        )

    async def _toc(self, request):
        pages = [{'artifactId': page_id, 'id': f'page-{idx}'} for idx, page_id in enumerate(self.page_ids)]
        pages.append({'artifactId': f'{self.page_ids[0]}#anchor', 'id': 'page-0'})
        pages.append({'artifactId': 'previewlimit', 'id': 'previewlimit'})
        return web.json_response({'pages': pages, 'sections': self.sections})

    async def _page_turn(self, request):
        return web.json_response(self.page_turn)

    async def _artifact(self, request):
        page_id = request.match_info['page_id']
        if request.match_info['token'] != CHECKOUT_TOKEN or page_id not in self.artifacts:
            return web.Response(status=404)
        content_type = 'application/xhtml+xml' if page_id.endswith('.xhtml') else 'application/pdf'
        return await self._respond(request, page_id, self.artifacts[page_id], content_type)

    async def _include(self, request):
        path = request.match_info['path']
        if request.match_info['token'] != CHECKOUT_TOKEN or path not in self.includes:
            return web.Response(status=404)
        content_type = 'text/css' if path.endswith('.css') else 'application/octet-stream'
        return await self._respond(request, path, self.includes[path], content_type)
