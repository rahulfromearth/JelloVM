public abstract class Main {
    public static int foo(int x) { return x + 42; }
    public static void foo(float x) {  }

    public static void main(String[] args) {
        // System.out.println("Hello, World");
        // System.out.println(foo(0)); // -> 1
        // System.out.println(32768);

        // System.out.println(1.0f);
        // System.out.println(0.0f);
        // System.out.println(2.0f);
        System.out.println(1.234f);
        System.out.println(42f);

        // py: int('111', 2) << 8 | int('11111111', 2)

        System.out.println(1234549828982398293L);
        // System.out.println(0L);
        // System.out.println();
        // System.out.println(new Integer()); // compiler error
        // System.out.println(foo(8)); // invokestatic
    }
}
