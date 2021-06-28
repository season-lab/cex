int foo() 
{
    return 0;
}

int bar_1() 
{
    return foo();
}

int bar_2() 
{
    return foo();
}

int baz() 
{
    return bar_1() + bar_2();
}

int main(int argc, char const *argv[])
{
    return baz();
}
