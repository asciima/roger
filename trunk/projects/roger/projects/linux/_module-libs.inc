
libs: wawo udns

libs_clean: wawo_clean udns_clean

wawo:
	@echo "building wawo begin"
	make -C$(LIB_WAWO_MAKEFILE_PATH) build=$(PRJ_BUILD) arch=$(PRJ_ARCH)
	@echo "building wawo finish"
	@echo 

wawo_clean:
	@echo "make -C$(LIB_WAWO_MAKEFILE_PATH) build=$(PRJ_BUILD) arch=$(PRJ_ARCH) clean"
	make -C$(LIB_WAWO_MAKEFILE_PATH) build=$(PRJ_BUILD) arch=$(PRJ_ARCH) clean
	
	
udns:
	@echo "build udns begin"
	make -C$(LIB_UDNS_MAKEFILE_PATH)
	@echo "build udns finish"
	@echo
	
udns_clean:
	make -C$(LIB_UDNS_MAKEFILE_PATH) clean