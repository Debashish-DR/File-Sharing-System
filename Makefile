CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lssl -lcrypto

all: server client

server: src/server.cpp src/tls_wrapper.h
	$(CXX) $(CXXFLAGS) src/server.cpp -o server $(LIBS)

client: src/client.cpp src/tls_wrapper.h
	$(CXX) $(CXXFLAGS) src/client.cpp -o client $(LIBS)

certs:
	chmod +x generate_certs.sh
	./generate_certs.sh

clean:
	rm -f server client

.PHONY: all clean certs
