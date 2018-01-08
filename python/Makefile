include $(src)/scripts/utils.mk

bdir:=$(obj)/python

TRACE_VIEW_OBJS =
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view.o
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view-store.o

ifdef BUILD_PYTHON_WORKS
PYTHON_SO_INSTALL := $(bdir)/ctracecmd.install
PYTHON_PY_PROGS := $(bdir)/event-viewer.install
PYTHON_PY_LIBS := $(bdir)/tracecmd.install $(bdir)/tracecmdgui.install
endif

$(bdir)/ctracecmd.so: ctracecmd.i $(LIBTRACECMD_STATIC) | $(bdir)
	swig -Wall -python -noproxy -I$(src)/include/traceevent -I$(src)/include/trace-cmd ctracecmd.i
	$(CC) -fpic -c $(CPPFLAGS) $(CFLAGS) $(PYTHON_INCLUDES) -o $(bdir)/ctracecmd_wrap.o ctracecmd_wrap.c
	$(CC) --shared $(LIBTRACECMD_STATIC) $(LDFLAGS) $(bdir)/ctracecmd_wrap.o -o $(bdir)/ctracecmd.so

$(bdir)/ctracecmdgui.so: ctracecmdgui.i $(LIBTRACECMD_STATIC) $(TRACE_VIEW_OBJS) | $(bdir)
	swig -Wall -python -noproxy -I$(src)/kernel-shark/include ctracecmdgui.i
	$(CC) -fpic -c  $(CPPFLAGS) $(CFLAGS) $(INCLUDES) $(PYTHON_INCLUDES) $(PYGTK_CFLAGS) -o $(bdir)/ctracecmdgui_wrap.o ctracecmdgui_wrap.c
	$(CC) --shared $(TRACE_VIEW_OBJS) $(LIBTRACECMD_STATIC) $(LDFLAGS) $(LIBS) $(CONFIG_LIBS) $(bdir)/ctracecmdgui_wrap.o -o $(bdir)/ctracecmdgui.so

$(bdir):
	@mkdir -p $(bdir)

$(PYTHON_SO_INSTALL): $(bdir)/%.install : $(bdir)/%.so force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

$(PYTHON_PY_PROGS): $(bdir)/%.install : %.py force
	$(Q)$(call do_install,$<,$(python_dir_SQ))

$(PYTHON_PY_LIBS): $(bdir)/%.install : %.py force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

install_python: $(PYTHON_SO_INSTALL) $(PYTHON_PY_PROGS) $(PYTHON_PY_LIBS)


clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.o $(bdir)/.*.d $(bdir)/ctracecmd_wrap.* $(bdir)/ctracecmdgui_wrap.*

force:
.PHONY: clean force
