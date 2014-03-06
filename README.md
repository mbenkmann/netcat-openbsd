netcat-openbsd
==============

This is Debian's fork of OpenBSD's netcat with extra features.

Branch 'master'
===============

This is an unmodified mirror of the Debian maintainer's git repository. There is no automatic sync, so expect this branch to be behind.

Branch 'lhm'
===============

This branch incorporates the following additional features:

* -H header:value switch to send additional headers to a CONNECT proxy. Useful if your proxy insists on a User-Agent header.
* -k is not limited to being used with -l. If used without -l, nc will keep re-connecting to the target port(s) whenever the connection terminates.
