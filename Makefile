APPLICATION = saml21-aes-gcm
BOARD ?= saml21-xpro
RIOTBASE ?= $(CURDIR)/../riot
QUIET ?= 1
DEVELHELP ?= 1

STDIO_INTERFACE ?= uart
SLEEP_SECONDS ?= 300
VERBOSE_DEBUG ?= 0
ENABLE_WAKEUP_PIN ?= 0

USEMODULE += od
USEMODULE += od_string
USEMODULE += fmt
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

include $(RIOTBASE)/Makefile.include
