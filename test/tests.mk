# List of test files
TESTS = test/test_inet_mton.o

# List of other objects that we need to pull in to make the tests work
OBJECTS = netcfg-common.o wireless.o

test/run: $(TESTS) $(OBJECTS) test/srunner.o
	$(CC) -o $@ $^ $(LDOPTS) -lcheck

test: test/run
	@echo "----------------------------------------"
	@echo
	@echo
	@test/run

.PHONY: test
