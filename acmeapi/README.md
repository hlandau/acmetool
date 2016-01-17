# ACME Client Library [![GoDoc](https://godoc.org/github.com/hlandau/acme/acmeapi?status.svg)](https://godoc.org/github.com/hlandau/acme/acmeapi) [![Build Status](https://travis-ci.org/hlandau/acme.svg?branch=master)](https://travis-ci.org/hlandau/acme) [![Issue Stats](http://issuestats.com/github/hlandau/acme/badge/issue?style=flat)](http://issuestats.com/github/hlandau/acme)

Basic ACME client library. [See godoc for the
API.](https://godoc.org/github.com/hlandau/acme/acmeapi)

This is distinct from acmetool in that it simply calls the server as you
request. It isn't smart and it doesn't manage certificate lifetimes. It can
be used by Go code independently of acmetool.

[For the acmetool command line tool, see
here.](https://github.com/hlandau/acme)

## Licence

    © 2015 Hugo Landau <hlandau@devever.net>    MIT License

