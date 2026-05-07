CXX = g++
CXXFLAGS = -Wall -std=c++11 -Iinclude
LDLIBS += -lpcap

SRC = deauth-attack.cpp src/dot11.cpp src/mac.cpp src/param.cpp
OBJ = $(SRC:.cpp=.o)

all: deauth-attack

deauth-attack: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	 rm -f deauth-attack *.o src/*.o
