import argparse
import logging
import os
import colorlog

from . import conf


def _set_parser():
    parser = argparse.ArgumentParser(
        description='TZ code generator for Authentic Execution')
    parser.add_argument('-l', '--loglevel', nargs='?',
                        default=conf.DEFAULT_LOG_LEVEL, type=__log_level)
    parser.add_argument('-i', '--input', required=True,
                        type=__input_dir, help='Input folder of the software module')
    parser.add_argument('-o', '--output', required=True,
                        type=__output_dir, help='Output folder of the software module')
    parser.add_argument('-v', '--vendor-id', type=__int16bits, required=False,
                        default=conf.DEFAULT_VENDOR_ID, help='Vendor ID')

    return parser


def _set_logging(loglevel):
    log = logging.getLogger()

    format_str = '%(asctime)s.%(msecs)03d - %(levelname)-8s: %(message)s'
    date_format = '%H:%M:%S'  # '%Y-%m-%d %H:%M:%S'
    if os.isatty(2):
        cformat = '%(log_color)s' + format_str
        colors = {'DEBUG': 'reset',
                  'INFO': 'bold_green',
                  'WARNING': 'bold_yellow',
                  'ERROR': 'bold_red',
                  'CRITICAL': 'bold_red'}
        formatter = colorlog.ColoredFormatter(cformat, date_format,
                                              log_colors=colors)
    else:
        formatter = logging.Formatter(format_str, date_format)

    log.setLevel(loglevel)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)


def __log_level(arg):
    arg = arg.lower()

    if arg == "critical":
        return logging.CRITICAL
    if arg == "error":
        return logging.ERROR
    if arg == "warning":
        return logging.WARNING
    if arg == "info":
        return logging.INFO
    if arg == "debug":
        return logging.DEBUG
    if arg == "notset":
        return logging.NOTSET

    raise argparse.ArgumentTypeError("Invalid log level")


def __input_dir(arg):
    if os.path.isdir(arg):
        return arg
    raise argparse.ArgumentTypeError("Input dir does not exist")


def __output_dir(arg):
    if not os.path.exists(arg):
        return arg
    raise argparse.ArgumentTypeError(
        f"Output dir {arg} already exists")


def __int16bits(arg):
    arg = int(arg, 0)
    if arg < 0 or arg > 65535:
        raise argparse.ArgumentTypeError(
            "Invalid Vendor ID: must be between 0 and 65535")

    return arg
