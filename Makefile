SHELL=bash
SOURCE_ROOT_DIR = target/fuzzers
INSTRUMENTED_ROOT_DIR = target/instrumented
RUNNERS_ROOT_DIR = target/runners
FUZZERS_BIN_DIR = target/out

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

all : internal_single $(FUZZER_CLASSES) $(INSTRUMENTED_DIRS) $(RUNNER_CLASSES) $(FUZZERENTRY_OBJECTS)

$(FUZZER_CLASSES) : $(FUZZER_SOURCES)
	for f in $^; do $(JAVAC) $(JAVA_FUZZER_CLASSPATH) ./$$f; done

$(INSTRUMENTED_DIRS) : $(FUZZER_FULLDIRS)
	for f in $^; do java -cp internal/single/kelinci/instrumentor/build/libs/kelinci.jar edu.cmu.sv.kelinci.instrumentor.Instrumentor -i ./$$f -o $@; done

$(RUNNER_SOURCES) :
	mkdir -p $(dir $@)
	cp internal/per_target/FuzzerRunner.java $@

$(RUNNER_CLASSES) : $(RUNNER_SOURCES)
	for f in $(FUZZER_DIRS); do javac -cp $(INSTRUMENTED_ROOT_DIR)/$$f/ $(RUNNERS_ROOT_DIR)/$$f/FuzzerRunner.java; done


$(FUZZERENTRY_OBJECTS) : $(FUZZER_CLASSES) $(INSTRUMENTED_DIRS) $(RUNNER_CLASSES)
	for f in $(FUZZER_DIRS); do mkdir -p $(FUZZERS_BIN_DIR)/$$f; clang++ -std=c++11 -Wall -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -c internal/per_target/fuzzerentry.cpp -o $(FUZZERS_BIN_DIR)/$$f/fuzzerentry.o; done


internal_single:
	make -C internal/single


clean:
	make -C internal/single clean
	rm -rf target/fuzzers/asn1/fuzzertarget/*.class
	rm -rf target/fuzzers/x509/fuzzertarget/*.class
	rm -rf $(INSTRUMENTED_ROOT_DIR)
	rm -rf $(RUNNERS_ROOT_DIR)

