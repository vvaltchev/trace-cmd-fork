# trace-cmd version
TC_VERSION = 2
TC_PATCHLEVEL = 7
TC_EXTRAVERSION = dev

# file format version
FILE_VERSION = 6

MAKEFLAGS += --no-print-directory

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)

EXT = -std=gnu99
INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

prefix ?= /usr/local
bindir_relative = bin
bindir = $(prefix)/$(bindir_relative)
man_dir = $(prefix)/share/man
man_dir_SQ = '$(subst ','\'',$(man_dir))'
html_install = $(prefix)/share/kernelshark/html
html_install_SQ = '$(subst ','\'',$(html_install))'
img_install = $(prefix)/share/kernelshark/html/images
img_install_SQ = '$(subst ','\'',$(img_install))'
libdir ?= $(prefix)/lib
libdir_SQ = '$(subst ','\'',$(libdir))'
includedir = $(prefix)/include/trace-cmd
includedir_SQ = '$(subst ','\'',$(includedir))'

export man_dir man_dir_SQ html_install html_install_SQ INSTALL
export img_install img_install_SQ
export DESTDIR DESTDIR_SQ

ifeq ($(prefix),$(HOME))
plugin_dir = $(HOME)/.trace-cmd/plugins
python_dir = $(HOME)/.trace-cmd/python
var_dir = $(HOME)/.trace-cmd/
else
plugin_dir = $(libdir)/trace-cmd/plugins
python_dir = $(libdir)/trace-cmd/python
PLUGIN_DIR = -DPLUGIN_DIR="$(plugin_dir)"
PYTHON_DIR = -DPYTHON_DIR="$(python_dir)"
PLUGIN_DIR_SQ = '$(subst ','\'',$(PLUGIN_DIR))'
PYTHON_DIR_SQ = '$(subst ','\'',$(PYTHON_DIR))'
var_dir = /var
endif

# Shell quotes
bindir_SQ = $(subst ','\'',$(bindir))
bindir_relative_SQ = $(subst ','\'',$(bindir_relative))
plugin_dir_SQ = $(subst ','\'',$(plugin_dir))
python_dir_SQ = $(subst ','\'',$(python_dir))

VAR_DIR = -DVAR_DIR="$(var_dir)"
VAR_DIR_SQ = '$(subst ','\'',$(VAR_DIR))'
var_dir_SQ = '$(subst ','\'',$(var_dir))'

HELP_DIR = -DHELP_DIR=$(html_install)
HELP_DIR_SQ = '$(subst ','\'',$(HELP_DIR))'
#' emacs highlighting gets confused by the above escaped quote.

BASH_COMPLETE_DIR ?= /etc/bash_completion.d

export PLUGIN_DIR
export PYTHON_DIR
export PYTHON_DIR_SQ
export plugin_dir_SQ
export var_dir

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

SWIG_DEFINED := $(shell if swig -help &> /dev/null; then echo 1; else echo 0; fi)
ifeq ($(SWIG_DEFINED), 0)
BUILD_PYTHON := report_noswig
NO_PYTHON = 1
endif

ifndef NO_PYTHON
PYTHON		:= ctracecmd.so
PYTHON_GUI	:= ctracecmd.so ctracecmdgui.so

PYTHON_VERS ?= python

# Can build python?
ifeq ($(shell sh -c "pkg-config --cflags $(PYTHON_VERS) > /dev/null 2>&1 && which swig && echo y"), y)
	PYTHON_PLUGINS := plugin_python.so
	BUILD_PYTHON := $(PYTHON) $(PYTHON_PLUGINS)
	PYTHON_SO_INSTALL := ctracecmd.install
	PYTHON_PY_PROGS := event-viewer.install
	PYTHON_PY_LIBS := tracecmd.install tracecmdgui.install
endif
endif # NO_PYTHON

export PYTHON_PLUGINS

# $(call test-build, snippet, ret) -> ret if snippet compiles
#                                  -> empty otherwise
test-build = $(if $(shell sh -c 'echo "$(1)" | \
	$(CC) -o /dev/null -c -x c - > /dev/null 2>&1 && echo y'), $2)

# have udis86 disassembler library?
udis86-flags := $(call test-build,\#include <udis86.h>,-DHAVE_UDIS86 -ludis86)

define BLK_TC_FLUSH_SOURCE
#include <linux/blktrace_api.h>
int main(void) { return BLK_TC_FLUSH; }
endef

# have flush/fua block layer instead of barriers?
blk-flags := $(call test-build,$(BLK_TC_FLUSH_SOURCE),-DHAVE_BLK_TC_FLUSH)

ifeq ("$(origin O)", "command line")
  BUILD_OUTPUT := $(O)
endif

ifeq ($(BUILD_SRC),)
ifneq ($(BUILD_OUTPUT),)

define build_output
	$(if $(VERBOSE:1=),@)$(MAKE) -C $(BUILD_OUTPUT) 	\
	BUILD_SRC=$(CURDIR) -f $(CURDIR)/Makefile $1
endef

saved-output := $(BUILD_OUTPUT)
BUILD_OUTPUT := $(shell cd $(BUILD_OUTPUT) && /bin/pwd)
$(if $(BUILD_OUTPUT),, \
     $(error output directory "$(saved-output)" does not exist))

endif # BUILD_OUTPUT
endif # BUILD_SRC

srctree		:= $(if $(BUILD_SRC),$(BUILD_SRC),$(CURDIR))
objtree		:= $(CURDIR)
src		:= $(srctree)
obj		:= $(objtree)

export prefix bindir src obj

LIBS = -ldl

LIBTRACEEVENT_DIR = $(obj)/lib/traceevent
LIBTRACEEVENT_STATIC = $(LIBTRACEEVENT_DIR)/libtraceevent.a
LIBTRACEEVENT_SHARED = $(LIBTRACEEVENT_DIR)/libtraceevent.so

LIBTRACECMD_DIR = $(obj)/lib/trace-cmd
LIBTRACECMD_STATIC = $(LIBTRACECMD_DIR)/libtracecmd.a
LIBTRACECMD_SHARED = $(LIBTRACECMD_DIR)/libtracecmd.so

export LIBS
export LIBTRACEEVENT_DIR LIBTRACECMD_DIR

CONFIG_INCLUDES = 
CONFIG_LIBS	=
CONFIG_FLAGS	=

VERSION		= $(TC_VERSION)
PATCHLEVEL	= $(TC_PATCHLEVEL)
EXTRAVERSION	= $(TC_EXTRAVERSION)

N		=

export Q VERBOSE EXT

# Include the utils
include scripts/utils.mk

TRACECMD_VERSION = $(TC_VERSION).$(TC_PATCHLEVEL).$(TC_EXTRAVERSION)

INCLUDES = -I$(src) -I $(src)/include -I $(srctree)/../../include $(CONFIG_INCLUDES)
INCLUDES += -I$(src)/include/traceevent
INCLUDES += -I$(src)/include/trace-cmd
INCLUDES += -I$(src)/lib/traceevent/include
INCLUDES += -I$(src)/lib/trace-cmd/include
INCLUDES += -I$(src)/kernel-shark/include

include $(src)/features.mk

# Set compile option CFLAGS if not set elsewhere
CFLAGS ?= -g -Wall
CPPFLAGS ?=
LDFLAGS ?=

export CFLAGS
export INCLUDES

# Required CFLAGS
override CFLAGS += -D_GNU_SOURCE

ifndef NO_PTRACE
ifneq ($(call try-cc,$(SOURCE_PTRACE),),y)
	NO_PTRACE = 1
	override CFLAGS += -DWARN_NO_PTRACE
endif
endif

ifdef NO_PTRACE
override CFLAGS += -DNO_PTRACE
endif

ifndef NO_AUDIT
ifneq ($(call try-cc,$(SOURCE_AUDIT),-laudit),y)
	NO_AUDIT = 1
	override CFLAGS += -DWARN_NO_AUDIT
endif
endif

ifdef NO_AUDIT
override CFLAGS += -DNO_AUDIT
else
LIBS += -laudit
endif

# Append required CFLAGS
override CFLAGS += $(CONFIG_FLAGS) $(INCLUDES) $(PLUGIN_DIR_SQ) $(VAR_DIR)
override CFLAGS += $(udis86-flags) $(blk-flags)

$(obj)/%.o: $(src)/%.c
	$(Q)$(call do_compile)

%.o: $(src)/%.c
	$(Q)$(call do_compile)

TRACE_VIEW_OBJS =
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view.o
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view-store.o

TRACE_CMD_OBJS = trace-cmd.o trace-record.o trace-read.o trace-split.o trace-listen.o \
	 trace-stack.o trace-hist.o trace-mem.o trace-snapshot.o trace-stat.o \
	 trace-profile.o trace-stream.o trace-record.o trace-restore.o \
	 trace-check-events.o trace-show.o trace-list.o  \
	 trace-output.o trace-usage.o trace-msg.o

ALL_OBJS = $(TRACE_CMD_OBJS)

CMD_TARGETS = tc_version.h trace-cmd $(BUILD_PYTHON)


TARGETS = $(CMD_TARGETS)


#	cpp $(INCLUDES)

###
#    Default we just build trace-cmd
#
#    If you want kernelshark, then do:  make gui
###

all: all_cmd plugins show_gui_make

all_cmd: $(CMD_TARGETS)

gui: force $(CMD_TARGETS)
	$(Q)$(MAKE) -C $(src)/kernel-shark; \
	echo "gui build complete"

trace-cmd: $(TRACE_CMD_OBJS)
	$(Q)$(do_app_build)

trace-cmd: $(LIBTRACECMD_STATIC) $(LIBTRACEEVENT_STATIC)

kernelshark: force $(CMD_TARGETS)
	$(Q)$(MAKE) -C $(src)/kernel-shark $@

trace-view: force $(CMD_TARGETS)
	$(Q)$(MAKE) -C $(src)/kernel-shark $@

trace-graph: force $(CMD_TARGETS)
	$(Q)$(MAKE) -C $(src)/kernel-shark $@

$(LIBTRACEEVENT_SHARED): force
	$(Q)$(MAKE) -C $(src)/lib/traceevent libtraceevent.so

$(LIBTRACEEVENT_STATIC): force
	$(Q)$(MAKE) -C $(src)/lib/traceevent libtraceevent.a

$(LIBTRACECMD_STATIC): force $(obj)/plugins/trace_plugin_dir
	$(Q)$(MAKE) -C $(src)/lib/trace-cmd libtracecmd.a

$(LIBTRACECMD_SHARED): force $(obj)/plugins/trace_plugin_dir
	$(Q)$(MAKE) -C $(src)/lib/trace-cmd libtracecmd.so

libtraceevent.so: $(LIBTRACEEVENT_SHARED)
libtraceevent.a: $(LIBTRACEEVENT_STATIC)
libtracecmd.a: $(LIBTRACECMD_STATIC)
libtracecmd.so: $(LIBTRACECMD_SHARED)

libs: $(LIBTRACECMD_SHARED) $(LIBTRACEEVENT_SHARED)

plugins: force $(obj)/plugins/trace_plugin_dir $(obj)/plugins/trace_python_dir
	$(Q)$(MAKE) -C $(src)/plugins

tc_version.h: force
	$(Q)$(N)$(call update_version.h)

$(obj)/plugins/trace_plugin_dir: force
	$(Q)$(MAKE) -C $(src)/plugins trace_plugin_dir

$(obj)/plugins/trace_python_dir: force
	$(Q)$(MAKE) -C $(src)/plugins trace_python_dir


## make deps

all_objs := $(sort $(ALL_OBJS))
all_deps := $(all_objs:%.o=.%.d)

$(all_deps): tc_version.h

$(all_deps): .%.d: $(src)/%.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@;

$(all_objs) : %.o : .%.d

dep_includes := $(wildcard $(all_deps))

ifneq ($(dep_includes),)
 include $(dep_includes)
endif

show_gui_make:
	@echo "Note: to build the gui, type \"make gui\""
	@echo "      to build man pages, type \"make doc\""

PHONY += show_gui_make

tags:	force
	$(RM) tags
	find . -name '*.[ch]' | xargs ctags --extra=+f --c-kinds=+px

TAGS:	force
	$(RM) TAGS
	find . -name '*.[ch]' | xargs etags

cscope: force
	$(RM) cscope*
	find . -name '*.[ch]' | cscope -b -q

install_plugins: force
	$(Q)$(MAKE) -C $(src)/plugins $@

$(PYTHON_SO_INSTALL): %.install : %.so force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

$(PYTHON_PY_PROGS): %.install : %.py force
	$(Q)$(call do_install,$<,$(python_dir_SQ))

$(PYTHON_PY_LIBS): %.install : %.py force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

$(PYTHON_PY_PLUGINS): %.install : %.py force
	$(Q)$(call do_install_data,$<,$(plugin_dir_SQ))

install_python: $(PYTHON_SO_INSTALL) $(PYTHON_PY_PROGS) $(PYTHON_PY_LIBS) $(PYTHON_PY_PLUGINS)

install_bash_completion: force
	$(Q)$(call do_install_data,trace-cmd.bash,$(BASH_COMPLETE_DIR))

install_cmd: all_cmd install_plugins install_python install_bash_completion
	$(Q)$(call do_install,trace-cmd,$(bindir_SQ))

install: install_cmd
	@echo "Note: to install the gui, type \"make install_gui\""
	@echo "      to install man pages, type \"make install_doc\""

install_gui: install_cmd gui
	$(Q)$(call do_install,$(obj)/kernel-shark/trace-view,$(bindir_SQ))
	$(Q)$(call do_install,$(obj)/kernel-shark/trace-graph,$(bindir_SQ))
	$(Q)$(call do_install,$(obj)/kernel-shark/kernelshark,$(bindir_SQ))

install_libs: libs
	$(Q)$(call do_install,$(LIBTRACECMD_SHARED),$(libdir_SQ))
	$(Q)$(call do_install,$(LIBTRACEEVENT_SHARED),$(libdir_SQ))
	$(Q)$(call do_install,$(src)/include/traceevent/event-parse.h,$(includedir_SQ))
	$(Q)$(call do_install,$(src)/include/trace-cmd/trace-cmd.h,$(includedir_SQ))

doc:
	$(MAKE) -C $(src)/Documentation all

doc_clean:
	$(MAKE) -C $(src)/Documentation clean

install_doc:
	$(MAKE) -C $(src)/Documentation install

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c .*.d
	$(RM) tags TAGS cscope*
	$(MAKE) -C $(src)/lib/traceevent clean
	$(MAKE) -C $(src)/lib/trace-cmd clean
	$(MAKE) -C $(src)/kernel-shark clean
	$(MAKE) -C $(src)/plugins clean


##### PYTHON STUFF #####

report_noswig: force
	$(Q)echo
	$(Q)echo "    NO_PYTHON forced: swig not installed, not compling python plugins"
	$(Q)echo

PYTHON_INCLUDES = `pkg-config --cflags $(PYTHON_VERS)`
PYTHON_LDFLAGS = `pkg-config --libs $(PYTHON_VERS)` \
		$(shell python2 -c "import distutils.sysconfig; print distutils.sysconfig.get_config_var('LINKFORSHARED')")
PYGTK_CFLAGS = `pkg-config --cflags pygtk-2.0`

export PYTHON_INCLUDES
export PYTHON_LDFLAGS
export PYGTK_CFLAGS

ctracecmd.so: $(TCMD_LIB_OBJS) ctracecmd.i
	swig -Wall -python -noproxy -I$(src)/include/traceevent -I$(src)/include/trace-cmd ctracecmd.i
	$(CC) -fpic -c $(CPPFLAGS) $(CFLAGS) $(PYTHON_INCLUDES)  ctracecmd_wrap.c
	$(CC) --shared $(LIBTRACECMD_STATIC) $(LDFLAGS) ctracecmd_wrap.o -o ctracecmd.so

ctracecmdgui.so: trace-view $(LIBTRACECMD_STATIC)
	swig -Wall -python -noproxy -I$(src)/kernel-shark/include ctracecmdgui.i
	$(CC) -fpic -c  $(CPPFLAGS) $(CFLAGS) $(INCLUDES) $(PYTHON_INCLUDES) $(PYGTK_CFLAGS) ctracecmdgui_wrap.c
	$(CC) --shared $(TRACE_VIEW_OBJS) $(LIBTRACECMD_STATIC) $(LDFLAGS) $(LIBS) $(CONFIG_LIBS) ctracecmdgui_wrap.o -o ctracecmdgui.so

PHONY += python
python: $(PYTHON)

PHONY += python-gui
python-gui: $(PYTHON_GUI)

PHONY += python-plugin
python-plugin: $(PYTHON_PLUGINS)

plugin_python.so: force $(obj)/plugins/trace_python_dir
	$(Q)$(MAKE) -C $(src)/plugins plugin_python.so

dist:
	git archive --format=tar --prefix=trace-cmd-$(TRACECMD_VERSION)/ HEAD \
		> ../trace-cmd-$(TRACECMD_VERSION).tar
	cat ../trace-cmd-$(TRACECMD_VERSION).tar | \
		bzip2 -c9 > ../trace-cmd-$(TRACECMD_VERSION).tar.bz2
	cat ../trace-cmd-$(TRACECMD_VERSION).tar | \
		xz -e -c8 > ../trace-cmd-$(TRACECMD_VERSION).tar.xz

PHONY += force
force:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
