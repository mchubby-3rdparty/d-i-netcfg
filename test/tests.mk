# List of test files
TESTS = test/test_inet_mton.o						\
        test/test_inet_ptom.o						\
        test/test_netcfg_parse_cidr_address.o				\
        test/test_netcfg_network_address.o				\
        test/test_netcfg_gateway_reachable.o

# List of other objects that we need to pull in to make the tests work
OBJECTS = netcfg-common.o wireless.o ethtool-lite.o

test/run: $(TESTS) $(OBJECTS) test/srunner.o
	$(CC) -o $@ $^ $(LDOPTS) -lcheck

test: test/run
	@echo "----------------------------------------"
	@echo
	@echo
	@test/run

.PHONY: test
