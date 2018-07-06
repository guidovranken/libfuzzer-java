#include <string>
#include <stdexcept>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <jni.h>

namespace javafuzzer {

class Util {
    public:
        static jclass findClass(JNIEnv* env, const std::string classPath) {
            const auto ret = env->FindClass(classPath.c_str());
            if ( ret == NULL ) {
                throw std::runtime_error(std::string("Class '") + classPath + std::string("' not found"));
            }
            return ret;
        }

        static jmethodID findMethodID(JNIEnv* env, const jclass inClass,  const std::string methodName, const std::string signature) {
            const auto ret = env->GetStaticMethodID(inClass, methodName.c_str(), signature.c_str());
            if ( ret == NULL ) {
                throw std::runtime_error(std::string("Method '") + methodName + std::string("' not found"));
            }
            return ret;
        }
};


class JVM {
    private:
        JavaVM* jvm = NULL;
        JNIEnv* env = NULL;

    public:
        JVM(const std::string classpath) {
            JavaVMInitArgs args;
            JavaVMOption options[2];

            args.version = JNI_VERSION_1_4;
            args.nOptions = 2;
            const std::string exclasspath = std::string("-D") + classpath;
            options[0].optionString = strdup(exclasspath.c_str());
            options[1].optionString = (char*)"-Xmx4096m";

            args.options = options;
            args.ignoreUnrecognized = JNI_FALSE;

            if ( JNI_CreateJavaVM(&jvm, (void **)&env, &args) != JNI_OK ) {
                throw std::runtime_error(std::string("Cannot create Java VM"));
            }

            free(options[0].optionString);
        }

        JNIEnv* GetEnv(void) const {
            return env;
        }
};

class MethodRunner {
    protected:
        JVM& jvm;

    public:
        MethodRunner(JVM& _jvm) :
            jvm(_jvm)
        { }
};

class Kelinci : public MethodRunner {
    private:
        jclass kelinciClass = NULL;
        jmethodID kelinciClear = NULL;
        jmethodID kelinciGetCodeCoverage = NULL;
        jmethodID kelinciGetCodeIntensity = NULL;
        jmethodID kelinciGetMaxHeap = NULL;

    public:
        Kelinci(JVM& _jvm) :
            MethodRunner(_jvm),
            kelinciClass(Util::findClass(jvm.GetEnv(), "edu/cmu/sv/kelinci/Mem")),
            kelinciClear(Util::findMethodID(jvm.GetEnv(), kelinciClass, "clear", "()V")),
            kelinciGetCodeCoverage(Util::findMethodID(jvm.GetEnv(), kelinciClass, "getCodeCoverage", "()J")),
            kelinciGetCodeIntensity(Util::findMethodID(jvm.GetEnv(), kelinciClass, "getCodeIntensity", "()J")),
            kelinciGetMaxHeap(Util::findMethodID(jvm.GetEnv(), kelinciClass, "getMaxHeap", "()J"))
        { }

        void clear(void) {
            return jvm.GetEnv()->CallStaticVoidMethod(kelinciClass, kelinciClear);
        }
        long GetCodeCoverage(void) {
            return jvm.GetEnv()->CallStaticLongMethod(kelinciClass, kelinciGetCodeCoverage);
        }

        long GetCodeIntensity(void) {
            return jvm.GetEnv()->CallStaticLongMethod(kelinciClass, kelinciGetCodeIntensity) / 1000;
        }

        long GetMaxHeap(void) {
            return jvm.GetEnv()->CallStaticLongMethod(kelinciClass, kelinciGetMaxHeap);
        }
};

class Runner : public MethodRunner {
    private:
        jclass runnerClass = NULL;
        jmethodID runnerInit = NULL;
        jmethodID runnerRun = NULL;
        bool inited = false;

    public:
        Runner(JVM& _jvm) :
            MethodRunner(_jvm),
            runnerClass(Util::findClass(jvm.GetEnv(), "FuzzerRunner")),
            runnerInit(Util::findMethodID(jvm.GetEnv(), runnerClass, "init", "()V")),
            runnerRun(Util::findMethodID(jvm.GetEnv(), runnerClass, "run", "([B)Z"))
        { }

        void Init(void) {
            if ( inited == false ) {
                jvm.GetEnv()->CallStaticVoidMethod(runnerClass, runnerInit);
                inited = true;
            }
        }

        bool Run(const uint8_t* data, const size_t size) {
            jbyteArray byteArray = jvm.GetEnv()->NewByteArray(size);
            if ( byteArray == NULL ) {
                throw std::runtime_error(std::string("Cannot create byte array"));
            }
            jvm.GetEnv()->SetByteArrayRegion(byteArray, 0, size, (jbyte*)data);
            const bool ret = jvm.GetEnv()->CallStaticBooleanMethod(runnerClass, runnerRun, byteArray);
            jvm.GetEnv()->DeleteLocalRef(byteArray);

            if ( ret == true ) {
                throw std::runtime_error("Runner returned true, requesting a crash");
            }

            return ret;
        }
};

class Options {
    public:
        Options(void) {
            sensorType = JF_SENSOR_CODE_COVERAGE;
        }

        typedef enum {
            JF_SENSOR_CODE_COVERAGE,
            JF_SENSOR_INTENSITY,
        } jf_option_sensor_t;

        void SetSensorType(const jf_option_sensor_t _sensorType) {
            sensorType = _sensorType;
        }
        jf_option_sensor_t GetSensorType(void) const {
            return sensorType;
        }

    private:
        jf_option_sensor_t sensorType;
};

Options g_options;

} /* namespace javafuzzer */

extern "C" int LLVMFuzzerInitialize(int *argc, const char ***argv) {
    using namespace javafuzzer;

    for (int i = 0; i < *argc; i++) {
        if ( strcmp((*argv)[i], "--intensity") == 0 ) {
            g_options.SetSensorType(Options::JF_SENSOR_INTENSITY);
        }
    }

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size) {
    using namespace javafuzzer;
    static JVM jvm("java.class.path=.:instrumented");
    static Kelinci kelinci(jvm);
    static Runner runner(jvm);

    kelinci.clear();

    runner.Init();
    runner.Run(data, size);

    switch ( g_options.GetSensorType() ) {
        case    Options::JF_SENSOR_CODE_COVERAGE:
            return kelinci.GetCodeCoverage();
        case    Options::JF_SENSOR_INTENSITY:
            return kelinci.GetCodeIntensity();
        default:
            throw std::runtime_error("Invalid sensor type");
            return 0;
    }
}
