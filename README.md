Onion Salt
==========

[Documentation](https://droundy.github.io/arrayref)

The onion salt source code is an encryption protocol that generates
nested "onions" which can be used in an onion-like routing protocol.
For more information, see the paper in the paper subdirectory.

The onion salt paper, in contrast, is copyrighted.

Building
--------

To build onion salt, type make.  This should build both the code and
the paper.  It also will incidentally build TweetNaCl.  It does not,
however, build a library.  I recommend just including these C files
into your project if you want to use onion salt.

However, I also recommend that you don't use onion salt unless you
really understand what you are doing, and are qualified to review the
code yourself.

Alternatively, if you have fac, then you can build by simply typing
fac.

Running tests
-------------

You can run the test suite by running

    python3 tests/harness.py

[![Build Status](https://travis-ci.org/droundy/onionsalt.svg)](https://travis-ci.org/droundy/onionsalt)
