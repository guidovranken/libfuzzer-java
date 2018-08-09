SHELL=bash
SOURCE_ROOT_DIR = target/fuzzers
INSTRUMENTED_ROOT_DIR = target/instrumented
RUNNERS_ROOT_DIR = target/runners
FUZZERS_BIN_DIR = target/out
SHARED_DIR = target/shared

JAVA = java
JAVAC = javac

FUZZER_DIRS = $(patsubst $(SOURCE_ROOT_DIR)/%,%,$(shell find $(SOURCE_ROOT_DIR) -mindepth 1 -maxdepth 1 -type d ))
FUZZER_FULLDIRS = $(patsubst %,$(SOURCE_ROOT_DIR)/%,$(FUZZER_DIRS))
FUZZER_SOURCES = $(patsubst %,$(SOURCE_ROOT_DIR)/%/fuzzertarget/FuzzerTarget.java,$(FUZZER_DIRS))
FUZZER_CLASSES = $(patsubst %,$(SOURCE_ROOT_DIR)/%/fuzzertarget/FuzzerTarget.class,$(FUZZER_DIRS))
INSTRUMENTED_DIRS = $(patsubst %,$(INSTRUMENTED_ROOT_DIR)/%,$(FUZZER_DIRS))
INSTRUMENTED_OBJECTS = $(patsubst %,$(INSTRUMENTED_ROOT_DIR)/%/FuzzerTarget.class,$(FUZZER_DIRS))
RUNNER_SOURCES = $(patsubst %,$(RUNNERS_ROOT_DIR)/%/FuzzerRunner.java,$(FUZZER_DIRS))
RUNNER_CLASSES = $(patsubst %,$(RUNNERS_ROOT_DIR)/%/FuzzerRunner.class,$(FUZZER_DIRS))
FUZZERENTRY_OBJECTS = $(patsubst %,$(FUZZERS_BIN_DIR)/%/fuzzerentry.o,$(FUZZER_DIRS))
FUZZER_BINARIES = $(patsubst %,$(FUZZERS_BIN_DIR)/%/fuzzer,$(FUZZER_DIRS))

all : internal_single $(FUZZER_BINARIES)

$(FUZZER_CLASSES) : $(FUZZER_SOURCES)
	for f in $^; do $(JAVAC) -cp $(SHARED_DIR):$(JAVA_FUZZER_CLASSPATH) ./$$f; done

$(INSTRUMENTED_DIRS) : $(FUZZER_CLASSES)
	find $(SOURCE_ROOT_DIR) -mindepth 2 -maxdepth 2 ! -name fuzzertarget -exec rm -rf {} \;
	for f in $(FUZZER_DIRS); do cp -R $(SHARED_DIR)/* $(SOURCE_ROOT_DIR)/$$f/; $(JAVA) -cp $(JAVA_FUZZER_CLASSPATH):internal/single/kelinci/instrumentor/build/libs/kelinci.jar edu.cmu.sv.kelinci.instrumentor.Instrumentor -i $(SOURCE_ROOT_DIR)/$$f -o $(INSTRUMENTED_ROOT_DIR)/$$f; done

$(RUNNER_SOURCES) :
	mkdir -p $(dir $@)
	cp internal/per_target/FuzzerRunner.java $@

$(RUNNER_CLASSES) : $(RUNNER_SOURCES) internal/per_target/FuzzerRunner.java
	for f in $(FUZZER_DIRS); do $(JAVAC) -cp $(INSTRUMENTED_ROOT_DIR)/$$f/ $(RUNNERS_ROOT_DIR)/$$f/FuzzerRunner.java; done

$(FUZZERENTRY_OBJECTS) : $(FUZZER_CLASSES) $(INSTRUMENTED_DIRS) $(RUNNER_CLASSES) internal/per_target/fuzzerentry.cpp
	for f in $(FUZZER_DIRS); do mkdir -p $(FUZZERS_BIN_DIR)/$$f; clang++ -std=c++11 -Wall -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -DJAVA_FUZZER_CLASSPATH=$(JAVA_FUZZER_CLASSPATH):target/instrumented/$$f:target/runners/$$f -c internal/per_target/fuzzerentry.cpp -o $(FUZZERS_BIN_DIR)/$$f/fuzzerentry.o; done

$(FUZZER_BINARIES) : $(FUZZERENTRY_OBJECTS) libFuzzer.a
	for f in $(FUZZER_DIRS); do clang++ -Wall -Wl,-rpath,$(JAVA_HOME)/jre/lib/amd64/jli -Wl,-rpath,$(JAVA_HOME)/jre/lib/amd64/server $(JAVA_HOME)/jre/lib/amd64/jli/libjli.so $(JAVA_HOME)/jre/lib/amd64/server/libjvm.so $(FUZZERS_BIN_DIR)/$$f/fuzzerentry.o libFuzzer.a -lpthread -ldl -o $(FUZZERS_BIN_DIR)/$$f/fuzzer; done

internal_single:
	make -C internal/single

clean:
	make -C internal/single clean
	rm -rf $(INSTRUMENTED_ROOT_DIR)
	rm -rf $(RUNNERS_ROOT_DIR)
	rm -rf $(FUZZERS_BIN_DIR)
	find target/ -type f -name '*.class' -exec rm {} \;
	find $(SOURCE_ROOT_DIR) -mindepth 2 -maxdepth 2 ! -name fuzzertarget -exec rm -rf {} \;
