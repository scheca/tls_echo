CXX = g++
CXXFLAGS=`pkg-config --cflags libtls`
LDFLAGS=`pkg-config --libs libtls`

%.o: %.cpp
	$(CXX) -std=c++11 -c $< $(CXXFLAGS)

tls_echo: tls_echo.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lpthread

.PHONY: clean

clean:
	rm -f *.o tls_echo

all: tls_echo
