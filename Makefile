# SANITIZE = -fsanitize=address

all: test.exe

test.exe: test.cpp aes.cpp
	g++ $(SANITIZE) -o test.exe test.cpp

clean:
	rm -f *.exe *.bin
