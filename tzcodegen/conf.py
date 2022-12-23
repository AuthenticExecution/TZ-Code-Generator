import os

DEFAULT_LOG_LEVEL = "info"
DEFAULT_VENDOR_ID = 33
STUBS_FOLDER = os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "stubs")


# Stubs
STUB_PTA_H = "pta_attestation.h"
STUB_SPONGENT_H = "spongent.h"
STUB_AE_H = "authentic_execution.h"
STUB_SPONGENT = "spongent.c"
STUB_Makefile = "Makefile"
STUB_USER_TA_HEADER_DEFINES = "user_ta_header_defines.h"
STUB_SUB_MK = "sub.mk"
STUB_IMPORT = "import.c"
STUB_TA_H = "ta.h"
STUB_AUTH_EXEC = "authentic_execution.c"
STUB_CRYPTO = "crypto.c"
STUB_CRYPTO_H = "crypto.h"
STUB_CONNECTION = "connection.c"
STUB_CONNECTION_H = "connection.h"

# Starting entrypoint index
# 0 is set_key, 1 is attest, 2 is handle_input
START_ENTRY_INDEX = 3
# Starting indexes of inputs, outputs
# They need to have different indexes, because the `index` field in Connection does
# not distinguish between them. If the same index is used for different types, bad
# things can happen. Moreover, having these "ranges" allow us do identify what is
# an index: e.g., 25848 is an output, 44 is an input, etc.
# We believe 16384 values for each type is more than enough for a single module.
START_INPUT_INDEX = 0
START_OUTPUT_INDEX = 16384

OUTPUT_PATTERN = '^[ \t]*SM_OUTPUT[ \t]*\([ \t]*([a-zA-Z_][a-zA-Z_0-9]*)[ \t]*\)[ \t]*;[ \t]*$'
INPUT_PATTERN = ('^[ \t]*SM_INPUT[ \t]*\([ \t]*([a-zA-Z_][a-zA-Z_0-9]*)[ \t]*,'
                 '[ \t]*[a-zA-Z_][a-zA-Z_0-9]*[ \t]*,[ \t]*[a-zA-Z_][a-zA-Z_0-9]*[ \t]*\)')
ENTRY_PATTERN = ('^[ \t]*SM_ENTRY[ \t]*\([ \t]*([a-zA-Z_][a-zA-Z_0-9]*)[ \t]*,'
                 '[ \t]*[a-zA-Z_][a-zA-Z_0-9]*[ \t]*,[ \t]*[a-zA-Z_][a-zA-Z_0-9]*[ \t]*\)')
OUTPUT_REPL = "SM_OUTPUT_AUX(\\1, {});"
IO_SIGNATURE = ("void {}(TEE_Param params[4], unsigned char *data, uint32_t len);\n")
