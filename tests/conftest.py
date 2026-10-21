import aiohttp
import pytest
from fake_ebsco import SESSION_COOKIE, FakeEbsco

from ebsco_dl.ebsco_2_downloader import Ebsco2Downloader


@pytest.fixture(autouse=True)
def fast_retries(monkeypatch):
    monkeypatch.setattr(Ebsco2Downloader, 'retry_delay_seconds', staticmethod(lambda try_num: 0))


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """The downloader reads cookies.txt from the current working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def cookies_file(workdir):
    path = workdir / 'cookies.txt'
    path.write_text(
        '# Netscape HTTP Cookie File\n' f'127.0.0.1\tFALSE\t/\tFALSE\t2147483647\t{SESSION_COOKIE}\tsession-value\n'
    )
    return path


def start_fake_ebsco(book_format):
    server = FakeEbsco(book_format)
    server.start()
    return server


@pytest.fixture
def fake_epub():
    server = start_fake_ebsco('epub')
    yield server
    server.stop()


@pytest.fixture
def fake_pdf():
    server = start_fake_ebsco('pdf')
    yield server
    server.stop()


@pytest.fixture
def make_downloader(workdir):
    def make(server: FakeEbsco) -> Ebsco2Downloader:
        downloader = Ebsco2Downloader(str(workdir / 'books'), server.viewer_url, skip_cert_verify=False)
        downloader.max_dl_retries = 3
        # Seconds. Must stay below FakeEbsco.hang_seconds, so a hanging artifact counts as failed try.
        downloader.client_timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=0.5)
        return downloader

    return make
