all: fuzzer

kelinci/instrumentor/build/libs/kelinci.jar:
	cd kelinci/instrumentor; gradle build
fuzzertarget/fuzzertarget/FuzzerTarget.class : fuzzertarget/fuzzertarget/FuzzerTarget.java
	javac -cp $(JAVA_FUZZER_CLASSPATH):fuzzertarget/ fuzzertarget/fuzzertarget/FuzzerTarget.java
instrumented : fuzzertarget/fuzzertarget/FuzzerTarget.class kelinci/instrumentor/build/libs/kelinci.jar 
	rm -rf instrumented
	mkdir instrumented
	java -cp $(JAVA_FUZZER_CLASSPATH):kelinci/instrumentor/build/libs/kelinci.jar edu.cmu.sv.kelinci.instrumentor.Instrumentor -i fuzzertarget -o instrumented
FuzzerRunner.class : FuzzerRunner.java instrumented
	javac -cp $(JAVA_FUZZER_CLASSPATH):instrumented/ FuzzerRunner.java
fuzzerentry.o : fuzzerentry.cpp FuzzerRunner.class
	$(CXX) $(CXXFLAGS) -DJAVA_FUZZER_CLASSPATH="$(JAVA_FUZZER_CLASSPATH)" -std=c++11 -Wall -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -c fuzzerentry.cpp -o fuzzerentry.o
fuzzer : fuzzerentry.o libFuzzer.a
	$(CXX) $(CXXFLAGS) -Wall -Wl,-rpath,$(JAVA_HOME)/jre/lib/amd64/jli -Wl,-rpath,$(JAVA_HOME)/jre/lib/amd64/server $(JAVA_HOME)/jre/lib/amd64/jli/libjli.so $(JAVA_HOME)/jre/lib/amd64/server/libjvm.so fuzzerentry.o libFuzzer.a -lpthread -ldl -o fuzzer
clean:
	rm -rf kelinci/instrumentor/build
	rm -rf kelinci/instrumentor/.gradle
	rm -rf instrumented
	rm -rf FuzzerRunner.class
	rm -rf fuzzer fuzzerentry.o
	find -name '*.class' -exec rm {} \;
