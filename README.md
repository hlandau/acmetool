# ACME Client Utilities

**Experimental - Under Development**

- A command line tool for acquiring certificates using a certificate storage
  repository to automatically determine what certificates need to be requested.

- Acquiring a certificate is as simple as this:

  `# acmetool want example.com`

  If successfully acquired, the certificate will be placed in
  `/var/lib/acme/live/example.com/{cert,chain,fullchain,privkey}`.

  Running `acmetool --batch` as root on a cronjob will allow it to
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

  [Details on the state directory format.](https://github.com/hlandau/acme/blob/master/SCHEMA.md)

- Contains an ACME client library which can be used independently.

## TODO

- Currently authorizations must be completed using port 80 or 443, which is not
  very useful if you're already running a webserver. Possible solutions: Add
  some way to route /.well-known/acme-challenge requests to a special HTTP
  server running on a port other than 80, which can be enabled with
  unremarkable web server configuration directives; add a webroot mode.

## Licence

    © 2015 Hugo Landau <hlandau@devever.net>    MIT License

