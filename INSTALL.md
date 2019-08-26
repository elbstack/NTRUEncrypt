Installation Instructions
=========================

If you downloaded a release tarball just run
    
    $ ./configure && make check

Ensure that all of the tests completed successfully and
install by running
    
    $ make install


Usually on a fresh installed linux there will be missing packages during
some of those steps. The program will detect which packages are missing.
And you can use the this command to install  missing packages:

    $ apt-get install XX
(to install a package named XX)


Now you have libntruencrypt library correctly
installed in your system. Then you will need to map the shared library name
to the location of the corresponding shared library file using

    $ ldconfig

You can call this library at compiling with a flag -lntruencrypt.
For example if you need to run this [sample code](https://github.com/NTRUOpenSourceProject/NTRUEncrypt/tree/master/sample)

Assuming you installed libntruencrypt in the default path, 
you can check if you have everything installed correctly by

    $ gcc sample_NTRUEncrypt.c -lntruencrypt -I /usr/local/include/libntruencrypt/

Static linking (USE THIS!)

    $ cd sample
    $ gcc -static ntruCmdHandler -lntruencrypt -I /usr/local/include/libntruencrypt/ -lsodium -I /usr/local/include/sodium -lpthread -I /usr/include/libntru -o ntruCmdHandler


---------------------
If you got the source from git, run 

    $ ./autogen.sh 

to finish
setting up the autotools environment, then follow the instructions
above. Alternatively you can use use pristine-tar to extract a
release tarball from the repository. You can also see a list of
releases by running:
    
    $ pristine-tar list

and can generate a release tarball with, e.g.

    $ pristine-tar checkout libntruencrypt0_1.0.0.orig.tar.gz



Optional Features
=================

Configure options:
  --enable-simd
      Build libntruencrypt with fast polynomial multiplication
      routines. Requires a processor with SSSE3 instructions.
  --enable-coverage
      Link against libgcov and compile with the -coverage flag.
      Requires CC=gcc, and lcov. Coverage results can subsequently
      be gathered and analyzed by running:
      $ make coverage-html
  --disable-silent-rules
      Verbose output during compilation.

