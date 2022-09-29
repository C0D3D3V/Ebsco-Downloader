import os
import html

from pathlib import Path
from yt_dlp.utils import sanitize_filename, remove_start


class PathTools:
    """A set of methods to create correct paths."""

    restricted_filenames = False

    @staticmethod
    def to_valid_name(name: str) -> str:
        """Filtering invalid characters in filenames and paths.

        Args:
            name (str): The string that will go through the filtering

        Returns:
            str: The filtered string, that can be used as a filename.
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
        name = sanitize_filename(name, PathTools.restricted_filenames)
        name = name.strip('. ')
        name = name.strip()

        return name

    @staticmethod
    def sanitize_path(path: str):
        """
        @param path: A path to sanitize.
        @return: A path where every part was sanitized using to_valid_name.
        """
        drive_or_unc, _ = os.path.splitdrive(path)
        norm_path = os.path.normpath(remove_start(path, drive_or_unc)).split(os.path.sep)
        if drive_or_unc:
            norm_path.pop(0)

        sanitized_path = [
            path_part if path_part in ['.', '..'] else PathTools.to_valid_name(path_part) for path_part in norm_path
        ]

        if drive_or_unc:
            sanitized_path.insert(0, drive_or_unc + os.path.sep)
        return os.path.join(*sanitized_path)

    @staticmethod
    def pathstr_of_book(storage_path: str, book_title: str):
        """
        @param storage_path: The path where all files should be stored.
        @param title: The name of the book.
        @return: A path where the file should be saved.
        """
        path = str(Path(storage_path) / PathTools.to_valid_name(book_title))
        return path

    @staticmethod
    def path_of_book(storage_path: str, book_title: str):
        """
        @param storage_path: The path where all files should be stored.
        @param title: The name of the book.
        @return: A path where the file should be saved.
        """
        path = Path(storage_path) / PathTools.to_valid_name(book_title)
        return path
