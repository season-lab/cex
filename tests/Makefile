all: external_call external_multi_call external_linked_foo multiple_retsite pthread_once pthread_create virtual_many_fun

external_call:
	gcc -O0 external_call.c -o external_call.elf

external_multi_call:
	gcc -O0 external_multi_call.c -o external_multi_call.elf

external_linked_foo:
	gcc -O0 external_linked_foo.c -o external_linked_foo.elf -L./libs -lfoo

multiple_retsite:
	gcc -O0 multiple_retsite.c -o multiple_retsite.elf

pthread_once:
	gcc -O0 pthread_once.c -o pthread_once.elf -lpthread

pthread_create:
	gcc -O0 pthread_create.c -o pthread_create.elf -lpthread

virtual_many_fun:
	g++ -O0 virtual_many_fun.cpp -o virtual_many_fun.elf

clean:
	rm -f *.elf
