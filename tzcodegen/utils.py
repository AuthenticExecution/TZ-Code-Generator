import os
import re
from distutils import dir_util

from . import conf


class Error(Exception):
    pass


def _prepare_output_dir(input_d, output_d):
    dir_util.copy_tree(input_d, output_d)


def get_output_id():
    id_ = conf.START_OUTPUT_INDEX
    conf.START_OUTPUT_INDEX += 1
    return id_


def _parse_annotations(file):
    with open(file, "r") as f:
        content = f.read()

    data = {}

    data["inputs"] = __parse_inputs(content)
    data["entrypoints"] = __parse_entrypoints(content)
    content, data["outputs"] = __parse_outputs(content)

    return content, data


def __parse_outputs(input_file):
    outputs = {}
    # check how many outputs have been declared in the input file
    p = re.compile(conf.OUTPUT_PATTERN, re.MULTILINE | re.ASCII)
    outputs_name = list(p.findall(input_file))

    num_outputs = len(outputs_name)

    # replace outputs with the replacement string
    output_file = input_file
    for i in range(num_outputs):
        num = get_output_id()
        output_file = p.sub(conf.OUTPUT_REPL.format(num), output_file, count=1)
        outputs.update({outputs_name[i]: num})

    return output_file, outputs


def __parse_inputs(content):
    return __parse(content, conf.INPUT_PATTERN, conf.START_INPUT_INDEX)


def __parse_entrypoints(content):
    return __parse(content, conf.ENTRY_PATTERN, conf.START_ENTRY_INDEX)


def __parse(content, pattern, start_index):
    p = re.compile(pattern, re.MULTILINE | re.ASCII)
    inputs = p.findall(content)

    return {v: i for (i, v) in enumerate(inputs, start_index)}


def add_io_declarations(file, data):

    with open(file, "r") as f:
        input_file = f.read()

    inputs_str = ""
    entrys_str = ""
    outputs_str = ""

    inputs = list(data["inputs"].keys())
    outputs = list(data["outputs"].keys())
    entrypoints = list(data["entrypoints"].keys())

    for input_ in inputs:
        inputs_str += conf.IO_SIGNATURE.format(input_)

    for output in outputs:
        outputs_str += conf.IO_SIGNATURE.format(output)

    for entrypoint in entrypoints:
        entrys_str += conf.IO_SIGNATURE.format(entrypoint)

    # prepare output file (inject code)
    output_file = input_file
    output_file = output_file.replace("{input_funcs}", inputs_str)
    output_file = output_file.replace("{output_funcs}", outputs_str)
    output_file = output_file.replace("{entry_funcs}", entrys_str)

    # write ta.h
    with open(file, "w") as f:
        f.write(output_file)


def fill_input_array(file, data):

    with open(file, "r") as f:
        input_file = f.read()

    # prepare instructions for filling the `input_funcs` array
    num_inputs = len(data["inputs"])
    array_fill = ",".join(data["inputs"])

    num_entrys = len(data["entrypoints"])
    entrys_fill = ",".join(data["entrypoints"])

    # prepare output file (inject code)
    output_file = input_file
    output_file = output_file.replace("{num_inputs}", str(num_inputs))
    output_file = output_file.replace("{fill_inputs}", array_fill)

    output_file = output_file.replace("{num_entrys}", str(num_entrys))
    output_file = output_file.replace("{fill_entrys}", entrys_fill)

    # write output file
    with open(file, "w") as f:
        f.write(output_file)


def _copy(src, des):
    with open(os.path.join(conf.STUBS_FOLDER, src), "r") as f:
        content = f.read()

    with open(os.path.join(des, src), "w") as f:
        f.write(content)

def _mkdir(path):
    if not os.path.exists(path):
        os.mkdir(path)
