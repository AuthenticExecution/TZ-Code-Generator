global-incdirs-y += include
srcs-y += {module_name}
srcs-y += spongent.c
srcs-y += authentic_execution.c
srcs-y += crypto.c
srcs-y += connection.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
