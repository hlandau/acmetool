% ACME Client Utilities

**Experimental - Under Development**

- A command line tool for acquiring certificates using a certificate storage
  repository to automatically determine what certificates need to be requested.

- Acquiring a certificate is as simple as this:

    # acmetool want example.com

  If successfully acquired, the certificate will be placed in
  /var/lib/acme/live/example.com/{cert,chain,fullchain,privkey}.

  Running `acmetool` as root on a cronjob will allow it to automatically
  reacquire certificates before they expire. The certificate data in
  `/var/lib/acme/live/example.com` will be updated automatically with the new
  certificate. acmetool can optionally invoke a shell script after having
  changed certificates if you need to reload a webserver.

- Works with Let's Encrypt.

- Contains an ACME client library which can be used independently.

Licence
-------

    © 2015 Hugo Landau <hlandau@devever.net>    MIT License

