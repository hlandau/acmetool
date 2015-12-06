# ACME Client Utilities [![Build Status](https://travis-ci.org/hlandau/acme.svg?branch=master)](https://travis-ci.org/hlandau/acme)

acmetool is an easy-to-use command line tool for automatically acquiring
certificates from ACME servers (such as Let's Encrypt). Designed to flexibly
integrate into your webserver setup to enable automatic verification. Unlike
the official Let's Encrypt client, this doesn't modify your web server
configuration.

You can perform verifications using port 80 or 443 (if you don't yet have a
server running on one of them); via webroot; by configuring your webserver to
proxy requests for `/.well-known/acme-challenge/` to a special port (402) which
acmetool can listen on; or by configuring your webserver not to listen on port
80, and instead running acmetool's built in HTTPS redirector (and challenge
responder) on port 80. This is useful if all you want to do with port 80 is
redirect people to port 443.

You can run acmetool on a cron job to renew certificates automatically (`acmetool --batch`).  The
preferred certificate for a given hostname is always at
`/var/lib/acme/live/HOSTNAME/{cert,chain,fullchain,privkey}`. You can configure
acmetool to reload your webserver automatically when it renews a certificate.

acmetool is intended to be "magic-free". All of acmetool's state is stored in a
simple, comprehensible directory of flat files. [The schema for this directory
is documented.](https://github.com/hlandau/acme.t/blob/master/doc/SCHEMA.md)

acmetool is intended to work like "make". The state directory expresses target
domain names, and whenever acmetool is invoked, it ensures that valid
certificates are available to meet those names. Certificates which will expire
soon are renewed. acmetool is thus idempotent and minimises the use of state.

acmetool can optionally be used [without running it as
root.](https://github.com/hlandau/acme.t/blob/master/doc/NOROOT.md) If you have
existing certificates issued using the official client, acmetool can import
those certificates, keys and account keys (`acmetool import-le`).

## Getting Started

[**Binary releases are also available.**](https://github.com/hlandau/acme/releases)

You will need Go installed.

If you are on Linux, you will need to make sure the development files for
`libcap` are installed. This is probably a package for your distro called
`libcap-dev` or `libcap-devel` or similar.

```bash
$ git clone https://github.com/hlandau/acme.t
$ cd acme.t
$ make && sudo make install

# Run the quickstart wizard. Sets up account, cronjob, etc.
$ sudo acmetool quickstart

# Configure your webserver to serve challenges if necessary.
# See https://github.com/hlandau/acme.t/blob/master/doc/WSCONFIG.md
$ ...

# Request the hostnames you want:
$ sudo acmetool want example.com www.example.com

# Now you have certificates:
$ ls -l /var/lib/acme/live/example.com/
```

<!-- # Renew certificates automatically:
# Change '42' to a random integer in [0,59] to distribute the load on the server.
$ sudo /bin/sh -c "echo '42 0 * * * root /usr/local/bin/acmetool -batch' > /etc/cron.d/acmetool" -->

The `quickstart` subcommand is a recommended wizard which guides you through the
setup of ACME on your system.

The `want` subcommand states that you want a certificate for the given hostnames.
(If you want separate certificates for each of the hostnames, run the want
subcommand separately for each hostname.)

The default subcommand, `reconcile`, is like "make" and makes sure all desired
hostnames are satisfied by valid certificates which aren't soon to expire.
`want` calls `reconcile` automatically.

If you run `acmetool reconcile` on a cronjob to facilitate automatic renewal,
pass `--batch` to ensure it doesn't attempt to interact with a terminal.

<!--
## Introduction

- A command line tool for acquiring certificates using a certificate storage
  repository to automatically determine what certificates need to be requested.

- Acquiring a certificate is as simple as this:

  `# acmetool want example.com`

  If successfully acquired, the certificate will be placed in
  `/var/lib/acme/live/example.com/{cert,chain,fullchain,privkey}`.

  Running `acmetool -``-batch` as root on a cronjob will allow it to
  automatically reacquire certificates before they expire. The certificate data
  in `/var/lib/acme/live/example.com` will be updated automatically with the
  new certificate. acmetool can optionally invoke a shell script after having
  changed certificates if you need to reload a webserver.

- Works with Let's Encrypt.

- acmetool is designed to work like `make`. A filesystem-based certificate
  repository expresses target domain names, and whenever acmetool is invoked,
  it ensures that valid certificates are available to meet those names.
  Certificates which will expire soon are renewed. The certificate matching
  each target is symlinked into `/var/lib/acme/live/DOMAIN`, so the right
  certificate for a given domain is always at `/var/lib/acme/live/DOMAIN`.

  acmetool is thus idempotent and it minimises the use of state. All state is
  explicitly kept in the certificate repository. There are essentially no
  proprietary file formats or configuration or state files; only a repository
  of certificates, a repository of ACME account keys and a set of targets.  On
  each invocation, ACME figures out which certificates satisfy which targets
  and obtains certificates as necessary.

  [Details on the state directory format.](https://github.com/hlandau/acme.t/blob/master/doc/SCHEMA.md)
-->

## Validation Options

<img src="https://i.imgur.com/w8TbgLL.png" align="right" alt="[screenshot]" />

**Webroot:** acmetool can place challenge files in a given directory, allowing your normal
web server to serve them. The files must be served from the path you specify at
`/.well-known/acme-challenge/`.

[Information on configuring your web server.](https://github.com/hlandau/acme.t/blob/master/doc/WSCONFIG.md)

**Proxy:** acmetool can respond to validation challenges by serving them on port 402. In
order for this to be useful, you must configure your webserver to proxy
requests under `/.well-known/acme-challenge/` to
`http://127.0.0.1:402/.well-known/acme-challenge`.

[Information on configuring your web server.](https://github.com/hlandau/acme.t/blob/master/doc/WSCONFIG.md)

**Redirector:** `acmetool redirector` starts an HTTP server on port 80 which redirects all
requests to HTTPS, as well as serving any necessary validation responses. The
`acmetool quickstart` wizard can set it up for you if you use systemd.
Otherwise, you'll need to configure your system to run `acmetool redirector
--service.uid=USERNAME --service.daemon=1` as a service, where `USERNAME` is
the username you want the daemon to drop to.

Make sure your web server is not listening on port 80.

**Listen:** If you are for some reason not running anything on port 80 or 443, acmetool
will use those ports. Either port being available is sufficient. This is only
really useful for development purposes.

## Library

The client library which these utilities use
(`github.com/hlandau/acme/acmeapi`) can be used independently by any Go code.
[![GoDoc](https://godoc.org/github.com/hlandau/acme/acmeapi?status.svg)](https://godoc.org/github.com/hlandau/acme/acmeapi)

[Source code.](https://github.com/hlandau/acme)

## Comparison with...

**Let's Encrypt Official Client:** A heavyweight Python implementation which is
a bit too “magic” for my tastes. Tries to mutate your webserver configuration
automatically.

acmetool is a single-file binary which only depends on basic system libraries
(on Linux, these are libc, libpthread, libcap, libattr). It doesn't do anything
to your webserver; it just places certificates at a standard location and can
also reload your webserver (whichever webserver it is) by executing hook shell
scripts.

acmetool isn't based around individual transactions for obtaining certificates;
it's about satisfying expressed requirements by any means necessary. Its
comprehensible, magic-free state directory makes it as stateless and idempotent
as possible.

**lego:** Like acmetool, [xenolf/lego](https://github.com/xenolf/lego) provides
a library and client utility. The utility provides commands for creating
certificates, but doesn't provide a compelling system for managing the lifetime
of the short-lived certificates offered by Let's Encrypt. The user is expected
to generate and install all certificates manually.

**gethttpsforfree:**
[diafygi/gethttpsforfree](https://github.com/diafygi/gethttpsforfree) provides
an HTML file which uses JavaScript to make requests to an ACME server and
obtain certificates. It's a functional user interface, but like lego it
provides no answer for the automation issue, and is thus impractical given the
short lifetime of certificates issued by Let's Encrypt.

### Comparison, list of client implementations

<table>
<tr><td></td><th>acmetool</th><th><a href="https://github.com/letsencrypt/letsencrypt">letsencrypt</a></th><th><a href="https://github.com/xenolf/lego">lego</a></th><th><a href="https://github.com/diafygi/gethttpsforfree">gethttpsforfree</a></th></tr>
<tr><td>Automatic renewal</td><td>Yes</td><td>Not yet</td><td>No</td><td>No</td></tr>
<tr><td>State management</td><td>Yes†</td><td>Yes</td><td>—</td><td>—</td></tr>
<tr><td>Single-file binary</td><td>Yes</td><td>No</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Quickstart wizard</td><td>Yes</td><td>Yes</td><td>No</td><td>No</td></tr>
<tr><td>Modifies webserver config</td><td>No</td><td>By default</td><td>No</td><td>No</td></tr>
<tr><td>Non-root support</td><td><a href="https://github.com/hlandau/acme.t/blob/master/doc/NOROOT.md">Optional</a></td><td>No</td><td>Optional</td><td>—</td></tr>
<tr><td>Supports Apache</td><td>Yes</td><td>Yes</td><td>—</td><td>—</td></tr>
<tr><td>Supports nginx</td><td>Yes</td><td>Experimental</td><td>—</td><td>—</td></tr>
<tr><td>Supports HAProxy</td><td>Yes</td><td>No</td><td>—</td><td>—</td></tr>
<tr><td>Supports any web server</td><td>Yes</td><td>Webroot‡</td><td>—</td><td>—</td></tr>
<tr><td>Authorization via webroot</td><td>Yes</td><td>Yes</td><td>—</td><td>Manual</td></tr>
<tr><td>Authorization via port 80 redirector</td><td>Yes</td><td>No</td><td>No</td><td>No</td></tr>
<tr><td>Authorization via proxy</td><td>Yes</td><td>No</td><td>No</td><td>No</td></tr>
<tr><td>Authorization via listener§</td><td>Yes</td><td>Yes</td><td>Yes</td><td>No</td></tr>
<tr><td>Import state from official client</td><td>Yes</td><td>—</td><td>—</td><td>—</td></tr>
</table>

† acmetool has a different philosophy to state management and configuration to
the Let's Encrypt client; see the beginning of this README.

‡ The webroot method does not appear to provide any means of reloading the
webserver once the certificate has been changed, which means auto-renewal
requires manual intervention.

§ Requires downtime.

This table is maintained in good faith; I believe the above comparison to be
accurate. If notified of any inaccuracies, I will rectify the table and publish
a notice of correction here.

## Licence

    © 2015 Hugo Landau <hlandau@devever.net>    MIT License

