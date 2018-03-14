# This file is part of the C++ dlopen mini HOWTO. You can find the complete
# HOWTO and/or updated versions at
# http://www.isotton.com/howtos/C++-dlopen-mini-HOWTO/
#
# Copyright 2002-2006 Aaron Isotton <aaron@isotton.com>
# Licensed under the GNU GPL.

example2: main.cpp polygon.hpp triangle.so
	$(CXX) $(CXXFLAGS) -o example2 main.cpp -ldl -g3

triangle.so: triangle.cpp polygon.hpp
	$(CXX) $(CXXFLAGS) -shared -fPIC -o triangle.so triangle.cpp -g3

clean:
	rm -f example2 triangle.so

.PHONY: clean
