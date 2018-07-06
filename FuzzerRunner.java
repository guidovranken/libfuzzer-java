import fuzzertarget.FuzzerTarget;
import java.io.PrintStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.IOException;

public class FuzzerRunner{
	public static void init() {
        PrintStream nullStream = new PrintStream(new NullOutputStream());
        System.setOut(nullStream);
        System.setErr(nullStream);
    }

	public static boolean run(byte[] input) {
        FuzzerTarget ft = new FuzzerTarget();
        return ft.run(input);
	}

    private static class NullOutputStream extends ByteArrayOutputStream {

        @Override
        public void write(int b) {}

        @Override
        public void write(byte[] b, int off, int len) {}

        @Override
        public void writeTo(OutputStream out) throws IOException {}
    }
}
