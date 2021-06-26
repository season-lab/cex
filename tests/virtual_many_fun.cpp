#include <stdio.h>

void f4() {
    puts("Hi!");
}

void f3() {
    f4();
}

void f2() {
    f3();
}

void f1() {
    f2();
}

class A {
public:
    virtual void foo() {
        f1();
    }
};

int main(int argc, char const *argv[])
{
    A* a = new A();

    a->foo();
    return 0;
}
