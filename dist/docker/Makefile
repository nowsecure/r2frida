all:
	docker build -t u20 .
	docker run -v $(shell pwd)/../..:/r2frida -ti u20 bash

test:
	@gcc stat.c && ./a.out
