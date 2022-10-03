# Note: type 'make Q=' to get make commands debug 
Q=@
PLUGIN_TASK_CONF='{"name": "s2opcua_server","plugin": "s2opcua","type": "north","schedule_type": 3,"schedule_day": 0,"schedule_time": 0,"schedule_repeat": 10,"schedule_enabled": true}'
PLUGIN_SERV_CONF='{"config":{}, "enabled" :"true", "name":"s2opcua_service", "plugin":"s2opcua", "type":"north"}'
CPPLINT_EXCLUDE='-build/include_subdir,-build/c++11,-whitespace/comments'

all: build install_plugin # insert_task
build:
	$(Q)mkdir -p build
	$(Q)cd build && cmake -DCMAKE_BUILD_TYPE=Release -DFLEDGE_INSTALL=$(FLEDGE_INSTALL) ..
	$(Q)make -C build -j4
	
unit_tests: install_certs
	$(Q)rm -rf build/tests/RunTests_coverage_html
	$(Q)mkdir -p build/tests
	$(Q)cd build && cmake -DCMAKE_BUILD_TYPE=Coverage -DFLEDGE_INSTALL=$(FLEDGE_INSTALL) ..
	$(Q)make -C build/tests RunTests_coverage_html -j4
	@echo "See unit tests coverage result in build/tests/RunTests_coverage_html/index.html"

clean:
	$(Q)rm -fr build
log:
	@echo "Showing logs from s2opcua_server plugin"
	$(Q)tail -f /var/log/syslog |grep -o 'Fledge s2opcua_.*$$'
	
check:
	@echo "Check validity of plugin 'libs2opcua.so'..."
	$(Q)! [ -z "$(FLEDGE_SRC)" ] || (echo "FLEDGE_SRC not set" && false)
	$(Q)$(FLEDGE_SRC)/cmake_build/C/plugins/utils/get_plugin_info build/libs2opcua.so plugin_info 2> /tmp/get_plugin_info.tmp
	$(Q)! ([ -s /tmp/get_plugin_info.tmp ] && cat /tmp/get_plugin_info.tmp)

install_certs:
	@echo "Install demo certificates to $(FLEDGE_ROOT)/data..."
	$(Q)mkdir -p $(FLEDGE_ROOT)/data/etc/certs/s2opc_srv/ > /dev/null
	$(Q)cp -arf ./samples/cert/* $(FLEDGE_ROOT)/data/etc/certs/s2opc_srv/

install_plugin: check install_certs
	@echo "Install plugin..."
	$(Q)sudo make -C build install
	
insert_task: del_plugin
	@echo "Insert plugin service in Fledge as task..."
	$(Q)! curl -sX POST http://localhost:8081/fledge/scheduled/task -d $(PLUGIN_TASK_CONF) \
	|  sed 's/^\(4.*\)/INSTALLATION FAILED : \1/; t; q 128 '
	@echo
	
insert_service: #del_plugin
	@echo "Insert plugin service in Fledge as service..."
	$(Q)! curl -sX POST http://localhost:8081/fledge/service -d $(PLUGIN_SERV_CONF) \
	|  sed 's/^\(4.*\)/INSTALLATION FAILED : \1/; t; q 128 '
	@echo

del_plugin:
	@echo "Delete plugin if already installed in FLEDGE..."
	$(Q)(curl -sX DELETE http://localhost:8081/fledge/scheduled/task/s2opcua_server | grep -o '"[ A-Za-z0-9_-]*deleted successfully."') || true
	$(Q)(curl -sX DELETE http://localhost:8081/fledge/service/s2opcua_service | grep -o '"[ A-Za-z0-9_-]*deleted successfully."') || true
	
cpplint:
	$(Q)cpplint --output=eclipse --repository=src --linelength=120 --filter=$(CPPLINT_EXCLUDE) --exclude=src/base_addrspace.c src/* include/*

test_sonar:
	$(Q)~/dev/.sonar/sonar-scanner-4.6.1.2450-linux/bin/sonar-scanner  \
          --define sonar.host.url="https://sonarcloud.io" \
          --define sonar.cfamily.build-wrapper-output=${BUILD_WRAPPER_OUT_DIR}\
          --define sonar.organization="fledge-power"\
          --define sonar.projectKey="fledge-power_fledge-north-s2opcua"\
          --define sonar.inclusions="**/src/plugin.cpp,**/src/opcua_server_*.cpp,**/include/opcua_server*.h"\
          --define sonar.coverageReportPaths="build/tests/RunTests_coverage_sonar-sonarqube.xml"
	
.PHONY: all clean build check del_plugin install_certs install_plugin insert_service insert_task cpplint unit_tests
