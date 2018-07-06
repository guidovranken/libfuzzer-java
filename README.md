# libfuzzer-java

Fuzz Java with libFuzzer.

You need:

* ```clang```
* ```gradle```
* ```libFuzzer-gv```: Get [libFuzzer-gv](https://github.com/guidovranken/libfuzzer-gv), build, and put ```libFuzzer.a``` in this project's root directory
* Oracle JDK. Set the environment variable ```JAVA_HOME``` to the JDK installation directory.

Put your code in the ```run``` method in ```fuzzertarget/fuzzertarget/FuzzerTarget.java```.
Return ```true``` from this method to force a crash and write the offending input to disk (for example if a certain exception was thrown).

Type ```CXX=clang++ make``` to build.

```CXXFLAGS``` can be empty (you do NOT need to instrument the C++ files).

Run with:

```
./fuzzer -custom_guided=1 -no_coverage_guided=1 -rss_limit_mb=6000 <corpus directory>
```

You can run it with less than 6GB, but you then also need to alter the ```-Xmx4096m``` option in ```fuzzerentry.cpp``` (preferably to a value +/- 2GB lower than your `rss_limit_mb`).

Add

```
-timeout=10
```

to crash on very slow inputs.

This project uses portions of [Kelinci](https://github.com/isstac/kelinci) by Rody Kersten.
