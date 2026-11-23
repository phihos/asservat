import java.util.ArrayList;
import java.util.List;

// A synthetic program for the tests of the JVM's diagnostics: threads with
// names to recognize wait in a method to recognize, and it holds objects
// of a class of its own.
public class Blocked {
    static final Object lock = new Object();
    static final List<Parcel> held = new ArrayList<>();

    static class Parcel {
        final byte[] content = new byte[1024];
    }

    static void waitForParcel() throws InterruptedException {
        synchronized (lock) {
            lock.wait();
        }
    }

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 1000; i++) {
            held.add(new Parcel());
        }
        for (int i = 0; i < 3; i++) {
            Thread t = new Thread(() -> {
                try {
                    waitForParcel();
                } catch (InterruptedException e) {
                }
            }, "asservat-courier-" + i);
            t.start();
        }
        System.out.println("waiting");
        Thread.sleep(Long.MAX_VALUE);
    }
}
