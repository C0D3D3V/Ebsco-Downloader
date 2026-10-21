import zipfile

import pypdf
import pytest
from fake_ebsco import BOOK_ID, BOOK_TITLE, USER_ID
from lxml import etree

from ebsco_dl.ebsco_2_downloader import Ebsco2Downloader
from ebsco_dl.utils import PathTools


def book_dir(workdir):
    return PathTools.path_of_book(str(workdir / 'books'), BOOK_TITLE)


def epub_path(workdir):
    return book_dir(workdir).with_name(book_dir(workdir).name + '.epub')


def pdf_path(workdir):
    return book_dir(workdir).with_name(book_dir(workdir).name + '.pdf')


class TestUrlParsing:
    def test_reads_ids_and_format_from_viewer_url(self, workdir):
        downloader = Ebsco2Downloader(
            str(workdir), f'https://research.ebsco.com/c/{USER_ID}/ebook-viewer/pdf/{BOOK_ID}?x=1', False
        )
        assert downloader.book_info.user_id == USER_ID
        assert downloader.book_info.book_format == 'pdf'
        assert downloader.book_info.book_id == BOOK_ID

    def test_rejects_unknown_url(self, workdir):
        with pytest.raises(NotImplementedError):
            Ebsco2Downloader(str(workdir), 'https://example.com/some/book', False)


def test_extract_artifact_ids_drops_anchors_duplicates_and_preview_limit():
    pages = [
        {'artifactId': 'a.xhtml', 'id': 'p1'},
        {'artifactId': 'a.xhtml#anchor', 'id': 'p1'},
        {'artifactId': 'b.xhtml', 'id': 'p2'},
        {'artifactId': 'previewlimit', 'id': 'previewlimit'},
    ]
    assert Ebsco2Downloader.extract_artifact_ids(pages) == (['a.xhtml', 'b.xhtml'], ['p1', 'p2'])


class TestSession:
    def test_missing_cookies_file_is_reported(self, fake_epub, make_downloader, capsys):
        make_downloader(fake_epub)
        assert 'No cookies file found' in capsys.readouterr().out

    def test_login_redirect_names_target_without_query(self, fake_epub, make_downloader):
        with pytest.raises(RuntimeError, match='redirected to: 127.0.0.1:[0-9]+/login') as error:
            make_downloader(fake_epub).run()
        assert 'secret' not in str(error.value)

    def test_book_info_that_is_no_json_gives_clear_error(self, fake_epub, make_downloader, cookies_file):
        from aiohttp import web

        fake_epub.book_info_override = web.Response(text='<html>Login</html>', content_type='text/html')
        with pytest.raises(RuntimeError, match='book info.*text/html.*instead of JSON'):
            make_downloader(fake_epub).run()

    def test_missing_checkout_token_gives_clear_error(self, fake_epub, make_downloader, cookies_file):
        fake_epub.page_turn = {'error': 'no license available'}
        with pytest.raises(RuntimeError, match='checkout token.*no license available'):
            make_downloader(fake_epub).run()


class TestEpub:
    def test_builds_epub_from_multi_line_xhtml(self, fake_epub, make_downloader, cookies_file, workdir):
        make_downloader(fake_epub).run()

        with zipfile.ZipFile(epub_path(workdir)) as epub:
            names = epub.namelist()
            assert names[0] == 'mimetype'
            assert epub.getinfo('mimetype').compress_type == zipfile.ZIP_STORED
            assert len(names) == len(set(names))
            for expected in [
                'EPUB/xhtml/ch1.xhtml',
                'EPUB/xhtml/ch2.xhtml',
                'EPUB/css/style.css',
                'EPUB/images/figure.png',
                'EPUB/fonts/book.woff',
                'OEBPS/content.opf',
                'OEBPS/toc.ncx',
            ]:
                assert expected in names
            content_opf = etree.fromstring(epub.read('OEBPS/content.opf'))
            toc_ncx = etree.fromstring(epub.read('OEBPS/toc.ncx'))

        opf = {'opf': 'http://www.idpf.org/2007/opf', 'dc': 'http://purl.org/dc/elements/1.1/'}
        assert content_opf.findtext('.//dc:title', namespaces=opf) == BOOK_TITLE
        assert [creator.text for creator in content_opf.findall('.//dc:creator', namespaces=opf)] == [
            'Ada Lovelace',
            'Alan Turing',
        ]
        spine = [item.get('idref') for item in content_opf.findall('.//opf:itemref', namespaces=opf)]
        assert spine == ['html1', 'html2']

        ncx = {'ncx': 'http://www.daisy.org/z3986/2005/ncx/'}
        nav_sources = [content.get('src') for content in toc_ncx.iterfind('.//ncx:content', namespaces=ncx)]
        assert nav_sources == ['../EPUB/xhtml/ch1.xhtml', '../EPUB/xhtml/ch2.xhtml']

    def test_leaves_out_missing_include_and_loads_css_only_once(
        self, fake_epub, make_downloader, cookies_file, workdir
    ):
        make_downloader(fake_epub).run()

        with zipfile.ZipFile(epub_path(workdir)) as epub:
            assert 'EPUB/images/missing.png' not in epub.namelist()
        assert fake_epub.request_counts['EPUB/css/style.css'] == 1

    def test_retries_page_that_hangs_or_is_busy(self, fake_epub, make_downloader, cookies_file, workdir):
        fake_epub.failures['EPUB/xhtml/ch1.xhtml'] = ['hang', 503]
        fake_epub.failures['EPUB/fonts/book.woff'] = [429]

        make_downloader(fake_epub).run()

        assert fake_epub.request_counts['EPUB/xhtml/ch1.xhtml'] == 3
        with zipfile.ZipFile(epub_path(workdir)) as epub:
            assert b'Chapter 1' in epub.read('EPUB/xhtml/ch1.xhtml')
            assert 'EPUB/fonts/book.woff' in epub.namelist()

    def test_page_that_keeps_failing_aborts(self, fake_epub, make_downloader, cookies_file, workdir):
        fake_epub.failures['EPUB/xhtml/ch2.xhtml'] = [503, 503, 503]

        with pytest.raises(RuntimeError, match='ch2.xhtml: 503'):
            make_downloader(fake_epub).run()
        assert not epub_path(workdir).exists()


class TestPdf:
    def test_merges_parts_with_outline(self, fake_pdf, make_downloader, cookies_file, workdir):
        make_downloader(fake_pdf).run()

        reader = pypdf.PdfReader(pdf_path(workdir))
        assert len(reader.pages) == 6
        outline = reader.outline
        assert [item.title for item in outline if not isinstance(item, list)] == ['Chapter 1', 'Chapter 2']
        assert [item.title for item in outline[-1]] == ['Section 2.1']
        assert reader.get_destination_page_number(outline[-1][0]) == 4

    def test_retries_part_that_hangs_or_is_busy(self, fake_pdf, make_downloader, cookies_file, workdir, capsys):
        fake_pdf.failures['pdf/part2.pdf'] = ['hang', 503]

        make_downloader(fake_pdf).run()

        assert len(pypdf.PdfReader(pdf_path(workdir)).pages) == 6
        output = capsys.readouterr().out
        assert '(Try 1 of 3) Unable to download part2.pdf' in output
        assert '(Try 2 of 3) Unable to download part2.pdf: 503' in output

    def test_part_that_keeps_failing_aborts_without_leftovers(
        self, fake_pdf, make_downloader, cookies_file, workdir, capsys
    ):
        fake_pdf.failures['pdf/part3.pdf'] = ['hang', 'hang', 'hang']

        with pytest.raises(SystemExit):
            make_downloader(fake_pdf).run()

        assert 'Could not download pdf/part3.pdf' in capsys.readouterr().out
        assert not pdf_path(workdir).exists()
        assert sorted(path.name for path in book_dir(workdir).iterdir()) == ['part1.pdf', 'part2.pdf']

    def test_resumes_cut_download_where_it_stopped(self, fake_pdf, make_downloader, cookies_file, workdir):
        fake_pdf.supports_ranges = True
        fake_pdf.failures['pdf/part2.pdf'] = ['cut']
        half = len(fake_pdf.artifacts['pdf/part2.pdf']) // 2

        make_downloader(fake_pdf).run()

        assert fake_pdf.range_headers['pdf/part2.pdf'] == [f'bytes={half}-']
        assert (book_dir(workdir) / 'part2.pdf').read_bytes() == fake_pdf.artifacts['pdf/part2.pdf']
        assert len(pypdf.PdfReader(pdf_path(workdir)).pages) == 6

    def test_starts_over_when_server_ignores_range(self, fake_pdf, make_downloader, cookies_file, workdir):
        fake_pdf.failures['pdf/part2.pdf'] = ['cut', 'cut']

        make_downloader(fake_pdf).run()

        assert fake_pdf.request_counts['pdf/part2.pdf'] == 3
        assert (book_dir(workdir) / 'part2.pdf').read_bytes() == fake_pdf.artifacts['pdf/part2.pdf']

    def test_not_found_part_is_not_retried(self, fake_pdf, make_downloader, cookies_file, workdir):
        fake_pdf.failures['pdf/part1.pdf'] = [404]

        with pytest.raises(SystemExit):
            make_downloader(fake_pdf).run()
        assert fake_pdf.request_counts['pdf/part1.pdf'] == 1

    def test_rerun_keeps_finished_parts_and_replaces_aborted_ones(
        self, fake_pdf, make_downloader, cookies_file, workdir
    ):
        parts_dir = book_dir(workdir)
        parts_dir.mkdir(parents=True)
        (parts_dir / 'part1.pdf').write_bytes(fake_pdf.artifacts['pdf/part1.pdf'])
        (parts_dir / 'part2.pdf.part').write_bytes(b'%PDF-half written')

        make_downloader(fake_pdf).run()

        assert 'pdf/part1.pdf' not in fake_pdf.request_counts
        assert fake_pdf.request_counts['pdf/part2.pdf'] == 1
        assert not list(parts_dir.glob('*.part'))
        assert len(pypdf.PdfReader(pdf_path(workdir)).pages) == 6
