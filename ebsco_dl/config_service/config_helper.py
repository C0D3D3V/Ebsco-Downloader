import os
import json

from pathlib import Path


class ConfigHelper:
    """
    Handles the saving, formatting and loading of the local configuration.
    """

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

    def __init__(self):
        self._whole_config = {}
        self.config_path = str(Path(self.get_user_config_directory()) / 'books-dl' / 'config.json')
        if self.is_present():
            self.load()
        else:
            config_dir_path = str(Path(self.get_user_config_directory()) / 'books-dl')
            if not os.path.exists(config_dir_path):
                try:
                    os.makedirs(config_dir_path)
                except FileExistsError:
                    pass
                self._save()

    def is_present(self) -> bool:
        # Tests if a configuration file exists
        return os.path.isfile(self.config_path)

    def load(self):
        # Opens the configuration file and parse it to a JSON object
        try:
            with open(self.config_path, 'r', encoding='utf-8') as config_file:
                config_raw = config_file.read()
                self._whole_config = json.loads(config_raw)
        except IOError:
            raise ValueError(f'No config found in "{self.config_path}"!')

    def _save(self):
        # Saves the JSON object back to file
        with open(self.config_path, 'w+', encoding='utf-8') as config_file:
            config_formatted = json.dumps(self._whole_config, indent=4)
            config_file.write(config_formatted)

    def get_property(self, key: str) -> any:
        # returns a property if configured
        try:
            return self._whole_config[key]
        except KeyError:
            raise ValueError(f'The Property {key} is not yet configured!')

    def set_property(self, key: str, value: any):
        # sets a property in the JSON object
        self._whole_config.update({key: value})
        self._save()

    def remove_property(self, key):
        # removes a property from the JSON object
        self._whole_config.pop(key, None)
        #                           ^ behavior if the key is not present
        self._save()

    # ---------------------------- GETTERS ------------------------------------

    def get_username(self) -> str:
        return self.get_property('username')

    def get_password(self) -> str:
        return self.get_property('password')

