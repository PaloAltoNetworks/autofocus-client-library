import os

# maintain python 2.7 compatibility for time being. GSRTConfig is a dependency on everything else,
# including ow-swagger-library, which supports both python2 and python3. I think we should
# stop supporting 2.x if needed, but since many people outside GSRT are still just beginning
# to transition to python3 yet use our client library, we should maintain support here. We want
# to continue to support other groups using and relying on OW and our client is the fastest way to that
# without an immediate hard blocker if they have a long python3 road ahead of them (aka, WF team)
# Also, it's an incredibly basic module so writing this blurb was more effort than adding compatibility.
try:
    import ConfigParser as configparser

    py2 = True
except ImportError:
    import configparser

    py2 = False


# Need to pull data from env variables > kube secret > config file


class GSRTConfig(object):
    """
    Quick module to handle a normalized config pull. Will search environment sections. To use environment varibles
    for invidual settings, the ENV should be named with {SECTION}_{KEY}. So for overwatch apikey, you should set a
    variable OVERWATCH_APIKEY={some apikey}
    """

    env_var_separator = "_"
    file_var_separator = "_"

    def __init__(self, config_section, defaults=None, config_path=None, secrets_dir=None,
                 throw_exception=False, allow_no_value=True):
        """
        Config files will be checked in /etc/panw be default. If a PANW_CONFIG env exists, it will pull the path from
        there When setting variable values, make sure that you can have an ALL_CAPS setting that will work without
        colliding in an environment variable Settings and sections should be lower_case_underscore

        """
        if defaults is None:
            defaults = {}

        if not secrets_dir and 'SECRETS_DIR' in os.environ:
            secrets_dir = os.environ.get("SECRETS_DIR")

        self.secrets_dir = secrets_dir

        # GSRTTECH-5222
        self.parser = configparser.ConfigParser(defaults, allow_no_value=allow_no_value)

        if not config_path and 'PANW_CONFIG' in os.environ:
            config_path = os.environ.get('PANW_CONFIG')

        if not config_path:
            for known_path in [os.path.expanduser("~") + "/.config/panw", "/opt/.config/panw", "/etc/panw/config"]:
                if os.path.isfile(known_path):
                    config_path = known_path
                    break

        self.config_path = config_path

        # Only read the file if the config_path is a true value
        if config_path:
            if os.path.isfile(config_path):
                self.parser.read(os.path.expanduser(config_path))
            else:
                raise Exception("PANW_CONFIG=%s is not a valid file" % config_path)

        # We'll stub out a blank section in case it doesn't exist, this prevents exceptions from being thrown
        if not self.parser.has_section(config_section):
            self.parser.add_section(config_section)

        self.config_section = config_section

        self.throw_exception = throw_exception

    def get(self, *args, **kwargs):
        """ Returns raw value

            Returns:
                str: raw value from env variable or config file
        """
        return self.get_setting(*args, **kwargs)

    def get_int(self, *args, **kwargs):
        """ Cast raw value to int

            Returns:
                int: value cast to int
        """
        # TODO: Make this mimic the config parser behavior. Does it throw exceptions?
        return int(self.get_setting(*args, **kwargs))

    def getint(self, *args, **kwargs):
        """ backwards compatibility with configparser """
        return self.get_int(*args, **kwargs)

    def get_boolean(self, *args, **kwargs):
        """ Returns boolean for parsed value. Parsed value must be one of

            ["1", "yes", "on", "true", "0", "no", "off", "false"]

            Returns:
                bool: boolean value representation of provided value

            Raises:
                ValueError: value provided was not a known boolean string value.
        """

        value = self.get_setting(*args, **kwargs)

        value = str(value).lower()
        if value in ["1", "yes", "on", "true"]:
            return True
        elif value in ["0", "no", "off", "false"]:
            return False
        else:
            raise ValueError("unexpected value '%s' provided" % value)

    def getboolean(self, *args, **kwargs):
        """ backwards compatibility with configparser """
        return self.get_boolean(*args, **kwargs)

    def to_dict(self, section=None, throw_exception=None):
        """Get all var names and values of a config section.

        Args:
            section (Optional[str]): Section to get items for. Use default section if None.

        Returns:
            dict: Dictionary of items for the specified section.
        """
        if not section:
            section = self.config_section

        # ensure section exists - needed here in addition to init for cases where user specifies section in
        # `get_setting()`
        if not self.parser.has_section(section):
            self.parser.add_section(section)

        if throw_exception is None:
            throw_exception = self.throw_exception

        env_vars = self._enumerate_env_vars(section)
        if env_vars:
            data = {}
            for full_key in env_vars:
                key = full_key.split(self.env_var_separator, maxsplit=1)[1]
                data[key] = os.environ.get(full_key)
            return data

        secrets_dir_vars = self._enumerate_secrets_dir_vars(section)
        if secrets_dir_vars:
            data = {}
            for key, file in secrets_dir_vars:
                key = key.split(self.file_var_separator, maxsplit=1)[1]
                data[key] = self._get_file_value(file)
            return data

        if throw_exception and not self.parser.has_section(section):
            raise ValueError(f"Section '{section}' doesn't exist")

        keys = list(self.parser[section].keys())
        return {key: self.get_setting(key, section=section, throw_exception=throw_exception) for key in keys}

    def get_setting(self, name, section=None, throw_exception=None):
        """
            Setting names should always be lower_case_underscore
            Well check the config and environment variables for the name. Environment variables will be made all caps
            when checked

            Args:
                name (str): attribute name to get
                section (Optional[str]): section name to retrieve attribute from, will default to self.config_section
                throw_exception (Optional[bool]): throw exceptions or not if invalid, default to self.throw_exception

        """

        if not section:
            section = self.config_section

        if self._env_key_exists(name, section):
            return self._get_from_env_var(name=name, section=section)

        if self.secrets_dir:
            try:
                return self._get_from_secrets_dir(name, section)
            except FileNotFoundError:
                pass

        if throw_exception is None:
            throw_exception = self.throw_exception

        # ensure section exists - needed here in addition to init for cases where user specifies section in
        # `get_setting()`
        if not self.parser.has_section(section):
            self.parser.add_section(section)

        if throw_exception:
            return self.parser.get(section, name)

        if py2:
            try:
                return self.parser.get(section, name)
            except configparser.NoOptionError:
                return None
        else:
            return self.parser.get(section, name, fallback=None)

    def _enumerate_env_vars(self, section):
        """Get all the envrionment variables for a section.

        Args:
            section (str): The name of the section to enumerate.

        Returns:
            list: names of all the enrionment variables in the specified section.
        """
        prefix = section.upper() + self.env_var_separator
        return [v for v in list(os.environ.keys()) if v.startswith(prefix)]

    def _enumerate_secrets_dir_vars(self, section):
        """Get all the secrets dir variables for a section.

        Returns:
            list(tuple(str)): Names and paths of all the secrets dir file variables in the specified section.
        """
        files = []
        prefix = section + self.file_var_separator
        if self.secrets_dir:
            for file in os.listdir(self.secrets_dir):
                full_path = os.path.join(self.secrets_dir, file)
                if os.path.isfile(full_path) and file.startswith(prefix):
                    files.append((file, full_path))
        return files

    def _env_key_exists(self, name, section):
        """Does an environment vairable env var exist?

        Args:
            name (str): Name of the variable.
            section (str): Name of the section for the variable.

        Returns:
            bool: Does the var exist?
        """
        return self._build_env_key(name, section) in os.environ.keys()

    def _build_env_key(self, name, section):
        """Create a full env var based on the name and section.

        Args:
            name (str): Name of the variable.
            section (str): Name of the section for the variable.

        Returns:
            str: The full name of the env var.
        """
        return section.upper() + self.env_var_separator + name.upper()

    def _build_file_key(self, name, section):
        """Create a full file name var based on the name and section.

        Args:
            name (str): Name of the variable.
            section (str): Name of the section for the variable.

        Returns:
            str: The full name of the file name var.
        """
        return section.upper() + self.file_var_separator + name.upper()

    def _get_from_env_var(self, key=None, name=None, section=None):
        """Get a value from an environment variable.

        Must provide either key, or name and section.

        Args:
            key Optional(str): Name of the key to fetch
            name Optional(str): Name of the variable.
            section Optional(str): Name of the section for the variable.

        Returns:
            The value of the environment variable.
        """
        if not key:
            if name and section:
                key = self._build_env_key(name, section)
        return os.environ.get(key)

    def _get_file_value(self, path):
        """Read and clean the value of file.

        Args:
            path (str): Path to the file.

        Returns:
            str: The content of the file.
        """
        with open(path, "r") as fh:
            return fh.read().rstrip()

    def _get_from_secrets_dir(self, name, section):
        """Get a value from a secrets dir file.

        Args:
            name (str): Name of the variable.
            section (str): Name of the section for the variable.

        Returns:
            str: Content of the file specified by the name and section, based in the specified secrets_dir.
        """
        secrets_file = os.path.join(self.secrets_dir,
                                    "{}_{}".format(section, name))

        return self._get_file_value(secrets_file)
# Automatically updated on Thu 17 Jun 2021 03:58:52 PM UTC
