#!/bin/sh

uname_str=`uname`

# Check if we're in a Mac OS X
if [ "$uname_str" == "Darwin" ]; then
	# We're installing on a Mac OS X

	# Get correct Makefiles into context
	mv Makefile Makefile.old
	mv Makefile.osx Makefile
	mv src/Makefile src/Makefile.old
	mv src/Makefile.osx src/Makefile

	# Build and Install package
	make && make install

	# Undo Makefiles context changes
	mv Makefile Makefile.osx
	mv Makefile.old Makefile
	mv src/Makefile src/Makefile.osx
	mv src/Makefile.old src/Makefile
else
	# This is for all other POSIX OSes
	make && make install
fi

