CXXFLAGS += -std=c++11

clean:
	rm -rf build *.o *.a *.so.* *.so a.out

build/libexplore.so.4.2: src/explore/explore_me.cpp src/explore/explore_me.h
	mkdir -p build
	${CXX} ${CXXFLAGS} -shared -fpic -o build/libexplore.so.4.2 $<

build/libexplore.so.4: build/libexplore.so.4.2
	mkdir -p build
	ln -s libexplore.so.4.2 build/libexplore.so.4

build/libexplore.so: build/libexplore.so.4
	mkdir -p build
	ln -s libexplore.so.4 build/libexplore.so

build/my_fuzz_test: build/libexplore.so
	@echo "Building $@"
	mkdir -p build
	cp -r my_fuzz_test_inputs build/
	# The FUZZ_TEST_CXXFLAGS and FUZZ_TEST_LDFLAGS environment variables
	# are set by cifuzz when it executes the build command. Those must
	# be passed to the compiler and linker (compiling and linking is
	# done in a single invocation here, so we pass both to $CXX here).
	${CXX} ${CXXFLAGS} ${FUZZ_TEST_CXXFLAGS} ${FUZZ_TEST_LDFLAGS} -o build/my_fuzz_test my_fuzz_test.cpp -Wl,-rpath '-Wl,$$ORIGIN' -Lbuild -lexplore

.PHONY: my_fuzz_test
my_fuzz_test: build/my_fuzz_test

crashing_fuzz_test.o: src/coverage/crashing_fuzz_test.c
	${CC} ${CFLAGS} ${FUZZ_TEST_CFLAGS} -c $<

crashing_fuzz_test: crashing_fuzz_test.o
	${CC} -o $@ crashing_fuzz_test.o ${LDFLAGS} ${FUZZ_TEST_LDFLAGS}
