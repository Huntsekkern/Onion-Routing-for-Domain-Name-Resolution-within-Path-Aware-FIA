# Node Package

This package contains both the nodes and network files 
as well as the protocol (sphinx and onion aka modified HORNET) files.

Splitting those files into two packages would make sense conceptually,
but does not gel well with Go requirement that the type on which
a method is called must be defined in the same package.

Network, Onion and Sphinx are rather generic abstractions and could be reused 
in a non-DNS context. \
While the 3 nodes files include DNS specific code and should be adapted for a more generic usage.

I'll repeat here that \
requester = stub resolver = source \
relay = router = intermediate relay \
resolver = recursive resolver = destination.
