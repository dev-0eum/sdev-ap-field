CXX = g++
CXXFLAGS = -Wall -std=c++11 
LDLIBS += -lpcap

all: airodump-test

airodump-test: airodump-test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f airodump-test *.o
