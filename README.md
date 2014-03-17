netcat-openbsd
==============

This is Debian's fork of OpenBSD's netcat with extra features.

Branch 'master'
===============

This is an unmodified mirror of the Debian maintainer's git repository. There is no automatic sync, so expect this branch to be behind.
Note that this branch does not have the quilt patches from debian/patches applied, so if you look at any of the C sources you'll be
looking at the original OpenBSD code.

Branch 'lhm'
===============

This branch incorporates the following additional features:

* -H header:value switch to send additional headers to a CONNECT proxy. Useful if your proxy insists on a User-Agent header.
* -k is not limited to being used with -l. If used without -l, nc will keep re-connecting to the target port(s) whenever the connection terminates.
* -m maxfork causes nc to handle up to maxfork connections in parallel child processes.
* -2 proxy makes nc act as a CONNECT/SOCKSv4/SOCKSv4a/SOCKS5 proxy.
* -2 host:port uses a connection to host:port as 2nd endpoint instead of stdin+stdout. 
* -x proxy1:port1+...+proxyN:portN establishes a proxy chain, using proxy1 to connect to proxy2,... and proxyN to connect to destination.
* permits multiple destination and port arguments to listen on/connect to multiple destinations

This branch has "quilt push -a" applied to it, so all the sources are in fully patched state with both the Debian patches
and the additional features from the list above.
