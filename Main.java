public abstract class Main {
    public static int foo(int x) { return x + 42; }
    public static void foo(float x) {  }

    public static void main(String[] args) {
        // System.out.println("Hello, World");
        // System.out.println(foo(0)); // -> 1
        // System.out.println(32768);
        System.out.println(1.234f);
        System.out.println(42f);
        System.out.println(1234549828982398293L);
        // System.out.println(0L);
        // System.out.println();
        // System.out.println(new Integer()); // compiler error
        // System.out.println(foo(8)); // invokestatic
    }
}
