import logging
import os
import sys
import uuid

from . import conf
from .utils import _parse_annotations, _prepare_output_dir, _copy, _mkdir, \
    add_io_declarations, fill_input_array
from .initialization import _set_parser, _set_logging


def __run(args):

    module_name = os.path.basename(os.path.normpath(args.input))
    out_include = os.path.join(args.output, "include")
    _mkdir(out_include)
    _copy(conf.STUB_PTA_H, out_include)
    _copy(conf.STUB_SPONGENT_H, out_include)
    _copy(conf.STUB_CRYPTO_H, out_include)
    _copy(conf.STUB_AE_H, out_include)
    _copy(conf.STUB_CONNECTION_H, out_include)

    _copy(conf.STUB_SPONGENT, args.output)
    _copy(conf.STUB_CRYPTO, args.output)
    _copy(conf.STUB_Makefile, args.output)
    _copy(conf.STUB_CONNECTION, args.output)
    # -------------------------------user_ta_header_defines-------------------------------
    _copy(conf.STUB_USER_TA_HEADER_DEFINES, args.output)
    u = uuid.uuid4()
    int_uuid = u.int
    
    n = [', 0x'] * 11
    n[::2] = ['{:012x}'.format(u.node)[i:i + 2] for i in range(0, 12, 2)]

    inject_uuid = "\t{ " + "0x{:08x}".format(u.time_low) + ", " \
        + "0x{:04x}".format(u.time_mid) + ", " + "0x{:04x}".format(u.time_hi_version) \
        + ", {" + "0x{:02x}".format(u.clock_seq_hi_variant)\
        + ", " + "0x{:02x}".format(u.clock_seq_low) + \
        ", " + "0x" + "".join(n) + "} }"

    with open(os.path.join(args.output, conf.STUB_USER_TA_HEADER_DEFINES), "r") as f:
        content = f.read()

    content = content.replace("{module_uuid}", inject_uuid)

    with open(os.path.join(args.output, conf.STUB_USER_TA_HEADER_DEFINES), "w") as f:
        f.write(content)
    # -----------------------------sub.mk----------------------------------------------
    _copy(conf.STUB_SUB_MK, args.output)
    with open(os.path.join(args.output, conf.STUB_SUB_MK), "r") as f:
        content = f.read()

    content = content.replace("{module_name}", module_name+".c")

    with open(os.path.join(args.output, conf.STUB_SUB_MK), "w") as f:
        f.write(content)

    # ---------------------------module----------------------------------------------
    out_src = os.path.join(args.output, module_name+".c")

    # In this section, we update TA:
    # - parse the annotations (inputs, outputs, entry points)
    # - add imports
    # parse annotations
    content, data = _parse_annotations(out_src)

    # read imports
    with open(os.path.join(conf.STUBS_FOLDER, conf.STUB_IMPORT), "r") as f:
        import_str = f.read()

    # write new content
    new_content = import_str + "\n" + "#include " + \
        "<" + module_name + ".h>\n" + content
    with open(out_src, "w") as f:
        f.write(new_content)
    # ------------------creating ta.h file--------------------------------------
    with open(os.path.join(conf.STUBS_FOLDER, conf.STUB_TA_H), "r") as f:
        ta_h = f.read()

    with open(os.path.join(out_include, module_name + ".h"), "w") as f:
        f.write(ta_h)

    add_io_declarations(os.path.join(out_include, module_name + ".h"), data)
    # ------------------------------------------------------------------
    ## Authentic Execution file ##
    # In this section, we add to the project all the needed for authentic execution
    # we also need to update some data structures with the information retrieved
    # before

    with open(os.path.join(conf.STUBS_FOLDER, conf.STUB_AUTH_EXEC), "r") as f:
        auth_exec = f.read()

    auth_exec = auth_exec.replace("{header_file}", "<" + module_name + ".h>")
    auth_exec = auth_exec.replace("{vendor_id}", str(args.vendor_id))

    with open(os.path.join(args.output, conf.STUB_AUTH_EXEC), "w") as f:
        f.write(auth_exec)

    fill_input_array(os.path.join(args.output, conf.STUB_AUTH_EXEC), data)

    return data, int_uuid


def generate(args):
    try:
        # check if the input dir is a correct Rust Cargo module
        logging.debug("Checking input project..")
        #cargo = _check_input_module(args.input)

        # copy dir
        logging.debug("Creating output project..")
        _prepare_output_dir(args.input, args.output)
        # generate code
        logging.debug("Generating code..")
        return __run(args)

    except Exception as e:
        logging.error(e)
        sys.exit(1)


def __main():
    # argument parser
    parser = _set_parser()
    args = parser.parse_args()

    # set logging params
    _set_logging(args.loglevel)
    generate(args)


if __name__ == "__main__":
    __main()
