import logging
import os.path
import sys
from argparse import ArgumentParser
from collections import namedtuple
from configparser import ConfigParser, NoOptionError, NoSectionError
from logging.handlers import SysLogHandler, WatchedFileHandler
from typing import Optional, List
from os import getenv

# noinspection PyUnresolvedReferences
import __main__
from str2bool import str2bool

try:
    from .colorlogger import ColorLogger as StreamHandler
except ImportError as e:
    from logging import StreamHandler


Argument = namedtuple("Argument", ["name", "type", "description", "default"], defaults=(str, "", None, ))


class Config:
    def __init__(self, options: Optional[List[Argument]]=None, section=None, logger: logging.Logger=None):
        """
        :param options: Tuple containing (option_name, option_type, option_description) with options
        that the program accepts.
        """
        self.options = {}

        if options is None:
            options = []  # type: List[Argument]

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

        options.append(Argument("log", str,
                                "Specify STDOUT or STDERR for console output, SYSLOG for syslog output or valid "
                                "file name. Default is STDERR.", default="STDERR"))
        options.append(Argument("log_level", str,
                                "Specify highest log level that should be logged. Can be DEBUG, INFO, "
                                "WARNING, ERROR, CRITICAL. Default is DEBUG.", default="DEBUG"))

        config = ConfigParser()

        parser = ArgumentParser()
        parser.add_argument("-f", "--config", help="Config file location")

        if section is None:
            section, _ = os.path.splitext(os.path.basename(__main__.__file__))
            section = section.replace("-", "_")

        if options is not None:
            for option in options:
                help_text = "{0}\nEnv: {1}_{2} or {2}.\nDefault: {3}"\
                    .format(option.description, section.upper(), option.name.upper(), option.default)

                if option.type == bool:
                    parser.add_argument("--%s" % (option.name, ), action="store_const", const=True, dest=option.name)
                    parser.add_argument("--no-%s" % (option.name, ), action="store_const", const=False,
                                        dest=option.name, help=help_text)
                else:
                    parser.add_argument("--%s" % (option.name, ), type=option.type, help=help_text)

        args = parser.parse_args()

        if args.config:
            config.read([args.config])

        if options is not None:
            for option in options:
                # Try to get env variable specific for this process.
                env_name = "{}_{}".format(section.upper(), option.name.upper())
                val = getenv(env_name, None)

                # Try to get global env variable
                if val is None:
                    val = getenv(option.name.upper(), None)

                if val is not None:
                    self.options[option.name] = self._convert_type(val, option.type)
                else:
                    # If no env variable is present, proceed to config file.
                    try:
                        val = config.get(section, option.name)
                        self.options[option.name] = self._convert_type(val, option.type)

                    except (NoOptionError, NoSectionError):
                        try:
                            val = config.get("DEFAULT", option.name)
                            self.options[option.name] = self._convert_type(val, option.type)
                        except NoOptionError:
                            self.options[option.name] = option.default
                        except NoSectionError:
                            self.options[option.name] = option.default

        # Assign config values from command line arguments, if present.
        for key, val in vars(args).items():
            if val is not None and key in self.options:
                self.options[key] = val

        self.setup_logging()

        self.logger.debug("Configuration dump:")
        for option, value in self.options.items():
            self.logger.debug("    %s=%s" % (option, value))

    @staticmethod
    def _convert_type(val, option_type):
        if option_type == bool:
            return str2bool(val)
        else:
            return option_type(val)

    def setup_logging(self):
        root = logging.getLogger()
        root.handlers = []
        root.name, _ = os.path.splitext(os.path.basename(__main__.__file__))

        output = self.get("log", "STDERR")

        formatter = logging.Formatter(
            "%(asctime)s %(name)s [%(process)s] %(levelname)s: %(message)s {%(filename)s:%(lineno)s}")

        if output == "STDERR":
            handler = StreamHandler(sys.stderr)
            handler.setFormatter(formatter)
        elif output == "STDOUT":
            handler = StreamHandler(sys.stdout)
            handler.setFormatter(formatter)
        elif output == "SYSLOG":
            handler = SysLogHandler("/dev/log")
            handler.setFormatter(logging.Formatter(
                "%(name)s[%(process)s] %(levelname)s: %(message)s {%(filename)s:%(lineno)s}"))
        else:
            handler = WatchedFileHandler(output)
            handler.setFormatter(formatter)

        try:
            level = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL
            }[self.get("log_level", "DEBUG")]
        except KeyError:
            level = logging.DEBUG

        root.addHandler(handler)
        root.setLevel(level)

        logging.captureWarnings(True)

    def get(self, option, default=None):
        return self.options.get(option, default)

    def __getattr__(self, name):
        return self.options[name]

    @staticmethod
    def argument(name, **kwargs):
        kwargs["name"] = name
        return kwargs
