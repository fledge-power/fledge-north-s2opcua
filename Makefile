# Note: type 'make Q=' to get make commands debug 
Q=@
PLUGIN_CONF='{"name": "s2opcua_srv","plugin": "s2opcua","type": "north","schedule_type": 3,"schedule_day": 0,"schedule_time": 0,"schedule_repeat": 30,"schedule_enabled": true}'

all: build install_plugin insert_plugin
build:
	$(Q)mkdir -p build
	$(Q)cd build && cmake -DFLEDGE_INSTALL=$(FLEDGE_INSTALL) ..
	$(Q)make -C build -j4
clean:
	$(Q)rm -fr build
check:
	@echo "Check validity of plugin 'libs2opcua.so'..."
	$(Q)! [ -z "$(FLEDGE_SRC)" ] || (echo "FLEDGE_SRC not set" && false)
	$(Q)$(FLEDGE_SRC)/cmake_build/C/plugins/utils/get_plugin_info build/libs2opcua.so plugin_info 2> /tmp/get_plugin_info.tmp
	$(Q)! ([ -s /tmp/get_plugin_info.tmp ] && cat /tmp/get_plugin_info.tmp)
        
install_plugin: check
	@echo "Install plugin..."
	$(Q)make -C build install
	@echo "Install demo certificates..."
	$(Q)mkdir -p $(FLEDGE_INSTALL)/data/etc/cert/ > /dev/null
	$(Q)cp -f ./samples/cert/* $(FLEDGE_INSTALL)/data/etc/certs/s2opc_srv/
	
insert_plugin: del_plugin
	@echo "Insert plugin service in Fledge..."
	$(Q)! curl -sX POST http://localhost:8081/fledge/scheduled/task -d $(PLUGIN_CONF) \
	|  sed 's/^\(4.*\)/INSTALLATION FAILED : \1/; t; q 128 '
	
	@echo
del_plugin:
	@echo "Delete plugin if already installed in FLEDGE..."
	$(Q)(curl -sX DELETE http://localhost:8081/fledge/scheduled/task/s2opcua_srv | grep -o '"[ A-Za-z0-9_-]*deleted successfully."') || true
	
		
.PHONY: all clean build check del_plugin install_plugin insert_plugin