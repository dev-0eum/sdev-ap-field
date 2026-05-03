CXX = g++
CXXFLAGS = -Wall -std=c++11
LDLIBS += -lpcap

all: deauth-attack

deauth-attack: deauth-attack.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f deauth-attack *.o
