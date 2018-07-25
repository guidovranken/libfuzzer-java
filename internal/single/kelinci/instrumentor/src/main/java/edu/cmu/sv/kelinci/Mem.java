package edu.cmu.sv.kelinci;

/**
 * Class to record branching, analogous to the shared memory in AFL.
 * 
 * Because we measure inside a particular target method, we need
 * a way to start/stop measuring. Therefore, the array can be cleared.
 * 
 * @author rodykers
 *
 */
public class Mem {
	
	public static long maxHeap = 0;
	public static long intensity = 0;
	public static final int SIZE = 65536;
	public static byte mem[] = new byte[SIZE];
	public static int prev_location = 0;
	
	public static void updateIntensity() {
		intensity++;
	}
	public static void updateHeapUsage() {
		Runtime runtime = Runtime.getRuntime();

		if ( (runtime.totalMemory() - runtime.freeMemory()) > maxHeap ) {
			maxHeap = runtime.totalMemory() - runtime.freeMemory();
		}
	}
	/**
	 * Clears the current measurements.
	 */
	public static void clear() {
		for (int i = 0; i < SIZE; i++) {
			if ( mem[i] != 0 ) {
				mem[i] = 1;
			}
		}
		intensity = 0;
		maxHeap = 0;
	}
	
	/**
	 * Prints to stdout any cell that contains a non-zero value.
	 */
	public static void print() {
		for (int i = 0; i < SIZE; i++) {
			if (mem[i] != 0) {
				System.out.println(i + " -> " + mem[i]);
			}
		}
	}

	public static long getCodeCoverage() {
		long num = 0;
		for (int i = 0; i < SIZE; i++) {
			if (mem[i] != 0) {
				num++;
			}
		}
		return num;
	}

	public static long getCodeIntensity() {
		return intensity;
	}

	public static long getMaxHeap() {
		return maxHeap;
	}
}
