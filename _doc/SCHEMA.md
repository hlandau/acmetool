ACME State Storage Specification
================================

The ACME State Storage Specification (ACME-SSS) specifies how an ACME client can store
state information in a directory on the local system in a way that facilitates
its own access to and mutation of its state and the exposure of certificates
and keys to other system services as required.

This specification relates to the use of ACME but has no official endorsement.

This specification is intended for use on POSIX-like systems.

Synopsis
--------

The following example shows a state directory configured to obtain a
certificate with hostnames example.com and www.example.com. No state other than
that shown below is used.

    /var/lib/acme
      desired/
        example.com         ; Target expression file
          ;; By default a target expression file expresses a desire for the
          ;; hostname which is its filename. The following YAML-format
          ;; configuration directives are all optional.
          names:
            - example.com
            - www.example.com
          provider: URL of ACME server

      live/
        example.com         ; Symlink to appropriate cert directory
        www.example.com     ;

      certs/
        (certificate/order ID)/
          cert              ; Contains the certificate
          chain             ; Contains the necessary chaining certificates
          fullchain         ; Contains the certificate and the necessary chaining certificates
          privkey           ; Symlink to a key privkey file
          account           ; Symlink to an account directory (required for ACMEv2)
          url               ; URL of the finalised order resource
          revoke            ; Empty file indicating certificate should be revoked
          revoked           ; Empty file indicating certificate has been revoked

      keys/
        (key ID)/
          privkey           ; PEM-encoded certificate private key

      accounts/
        (account ID)/
          privkey           ; PEM-encoded account private key

      conf/                 ; Configuration data
        target              ; This has the same format as a target expression file
                            ; and is used to specify defaults. It is used to specify
                            ; a default provider URL. Not all values which are valid
                            ; in a target expression file may be used.

        webroot-path        ; DEPRECATED.
        rsa-key-size        ; DEPRECATED.

                            ; Other, implementation-specific files may be placed in conf.

      tmp/                  ; (used for writing files only)

Preferred Location
------------------

All ACME state is stored within a directory, the State Directory. On UNIX-like
systems, this directory SHOULD be "/var/lib/acme".

Directory Tree
--------------

### desired

An ACME State Directory expresses targets in the form of desired hostnames for
which certificates are required. This normatively expresses the target set of
domains.

The desired hostnames list is a directory named "desired" inside the State
Directory, containing zero or more files. Each file represents a target.

The function of an implementation of this specification is simply this: to
ensure that currently valid certificates are always provisioned which provide
for all hostnames expressed across all targets.

Each target is a YAML file. The file schema looks like this:

    satisfy:
      names:
        - example.com
        - www.example.com
        - foo.example.com

    request:
      names:
        ...
      provider: (URL of ACME server)

    priority: 0

The target file is principally divided into "satisfy" and "request" sections.
The satisfy section controls the conditions which must be satisfied by a
certificate in order to satisfy this target. The request section controls the
parameters of a new certificate request made to satisfy the target.

**Conditions to be satisfied.** The "satisfy" section can contain the following values:

  - `names`: A list of hostname strings. If not set, and the filename is a valid
    hostname, defaults to a list containing only that hostname. Hostnames SHOULD
    be in lowercase with no trailing dot but hostnames not in this form MUST be
    accepted and so canonicalized. IDN domain names in Unicode form MUST be converted
    to their equivalent ASCII form. (All text files in a State Directory must be
    UTF-8 encoded.)

  - `key`: `type`: Optional string containing "", "rsa" or "ecdsa". If set to a
    non-empty value, only satisfied by keys with a public key of that type.

  - `margin`: Optional positive integer. If set, expresses the number of days
    before expiry at which a certificate should be replaced. The default value
    is implementation-dependent.

(The lumping of hostnames into different target files controls when separate
certificates are issued, and when single certificates with multiple SANs are
issued. For example, creating two empty files, `example.com` and
`www.example.com`, would result in two certificates. Creating a single file
`example.com` which specifies names to be satisfied of `example.com` and
`www.example.com` would result in one certificate with both names.)

**Certificate request parameters.** The "request" section can contain the following values:

  - `names`: A list of hostname strings. Defaults to the names set under "satisfy".
    This setting is specified for design parity, but it is not envisioned that
    a user will ever need to set it explicitly.

  - `provider`: A string which is the URL of an ACME server from which to request
    certificates. Optional; if not specified, an implementation-specific default
    ACME server is used.

**Backwards compatibility.** For compatibility with previous versions,
implementations SHOULD check for keys "names" and "provider" at the root level
and if present, move them to the "satisfy" and "request" sections respectively.

**Target set disjunction priority.** The "priority" value is special. It is an
integer defaulting to 0.

**Target set label.** The "label" value is an optional string value and
defaults to "".

**Target set disjunction procedure.** In order to ensure consistent and
deterministic behaviour, and to minimise the number of certificate requests
which need to be made in regard of overlapping name sets, the sets of names to
be satisfied by each target are modified to ensure that the sets are fully
disjoint. That is, any given hostname must appear in at most one target's list
of names to be satisfied.

The procedure operates as follows for all targets with a given label:

- Take the list of targets and sort it in descending order of priority value.
  For targets with equal priority, tiebreak using the number of hostnames to be
  satisfied in descending order. Where the number of hostnames is equal, the
  tiebreaker is implementation-specified, but SHOULD be deterministic.

- Now iterate through the targets in that order. Create an empty dictionary
  mapping hostnames to targets. This dictionary shall be called the
  Hostname-Target Mapping and should be retained in memory even after the
  disjunction procedure is completed.

    - For each hostname to be satisfied for a target, if that hostname is not
      already in the dictionary, add it, pointing to the given target.

    - Copy the list of hostnames to be satisfied by the given target, and
      remove any hostnames from it which were already in the dictionary (i.e.,
      where the map does not point to this target). This modified hostname list
      is called the reduced set of hostnames to be satisfied.

Keep both the full set of hostnames to be satisfied and the reduced set of
hostnames to be satisfied in memory for each target. The on-disk target files
are not modified.

Wildcard certificates may be requested just as the wildcard name would be
encoded in a certificate. For example, an empty file named `*.example.com`
could be created in the "desired" directory.

**Disjunction example.** This section is non-normative. Suppose that the
following targets were created:

    Target 01: a.example.com  b.example.com  c.example.com
    Target 02: a.example.com  b.example.com
    Target 03:                b.example.com  c.example.com
    Target 04: a.example.com                 c.example.com
    Target 05: a.example.com
    Target 06:                b.example.com
    Target 07:                               c.example.com
    Target 08: c.example.com  d.example.com  e.example.com  f.example.com
    Target 09: c.example.com  d.example.com
    Target 10: c.example.com  d.example.com  e.example.com

Suppose that all targets have the default priority zero and have filenames
"Target 01", etc. The targets would be sorted as follows. The hostnames
in brackets are not in the reduced set.

    Target 08: c.example.com  d.example.com  e.example.com  f.example.com
    Target 01: a.example.com  b.example.com [c.example.com]
    Target 10:[c.example.com][d.example.com][e.example.com]
    Target 02:[a.example.com][b.example.com]
    Target 03:               [b.example.com][c.example.com]
    Target 04:[a.example.com]               [c.example.com]
    Target 09:[c.example.com][d.example.com]
    Target 05:[a.example.com]
    Target 06:               [b.example.com]
    Target 07:                              [c.example.com]

Suppose that Target 01 was changed to have a priority of 10. The sorted,
reduced targets would now look like this:

    Target 01: a.example.com  b.example.com  c.example.com
    Target 08:[c.example.com] d.example.com  e.example.com  f.example.com
    Target 10:[c.example.com][d.example.com][e.example.com]
    Target 02:[a.example.com][b.example.com]
    Target 03:               [b.example.com][c.example.com]
    Target 04:[a.example.com]               [c.example.com]
    Target 09:[c.example.com][d.example.com]
    Target 05:[a.example.com]
    Target 06:               [b.example.com]
    Target 07:                              [c.example.com]

**Extensions for specific implementations: acmetool.** This section is
non-normative, added as a practicality since this document serves as both
specification and documentation. acmetool supports the following extensions:

    request:
      # Determines whether RSA or ECDSA keys are used. ECDSA keys must be
      # supported by the server. Let's Encrypt does not yet support ECDSA
      # keys, though support is imminent. Default RSA.
      key:
        type: rsa (must be "rsa" or "ecdsa")

        # RSA modulus size when using an RSA key. Default 2048 bits.
        #
        # Legacy compatibility: if not present, the number of bits may be
        # contained in a file "rsa-key-size" inside the conf directory.
        rsa-size: 2048

        # ECDSA curve when using an ecdsa key. Default "nistp256".
        #
        # It is strongly recommended that you use nistp256. Let's Encrypt
        # will not support nistp521.
        ecdsa-curve: nistp256 (must be "nistp256", "nistp384" or "nistp521")

        # If specified, specifies a key ID which should be used as the private
        # key for all generated requests. If not set or the key ID is not found,
        # generate a new key for every request.
        id: string

      # Request OCSP Must Staple in certificates. Defaults to false.
      ocsp-must-staple: true

      challenge:
        # Webroot paths to use when requesting certificates. Defaults to none.
        # This is usually used in the default target file. While you _can_ override
        # this in a specific target, you should think very carefully by doing so.
        # In almost all cases, it is better to use symlinks or aliases to ensure
        # that the same directory is used for all vhosts.
        #
        # Legacy compatibility: the file "webroot-path" in the conf directory
        # contains a list of webroot paths, one per line.
        webroot-paths:
          - /some/webroot/path/.well-known/acme-challenge

        # A list of additional ports to listen on. Each item can be a port
        # number, or an explicit bind address (e.g. "[::1]:402"). Specifying a
        # port number x is equivalent to specifying "[::1]:x" and "127.0.0.1:x".
        http-ports:
          - 80
          - 402
          - 4402

        # Defaults to true. If false, will not perform self-test but will assume
        # challenge can be completed. Rarely needed.
        http-self-test: true

        # Optionally set environment variables to be passed to hooks.
        env:
          FOO: BAR

### accounts

An ACME State Directory MUST contain a subdirectory "accounts" which contains
account-specific information. It contains zero or more subdirectories, each of
which relates to a specific account. Each subdirectory MUST be named after the
Account ID.

Each account subdirectory MUST contain a file "privkey" which MUST contain the
account private key in PEM form.

An ACME client which needs to request a certificate from a given provider (as
expressed by a target or used as a default) which finds that no account
corresponding to that provider URL exists should generate a new account key and
store it for that provider URL.

### keys

An ACME State Directory MUST contain a subdirectory "keys" which contains
private keys used for certificates. It contains zero or more subdirectories,
each of which relates to a specific key. Each subdirectory MUST be named after
the Key ID.

Each key subdirectory MUST contain a file "privkey" which MUST contain the
private key in PEM form.

An ACME client creates keys as necessary to correspond to certificates it
requests. An ACME client SHOULD create a new key for every certificate request.

### certs

An ACME State Directory MUST contain a subdirectory "certs" which contains
information about issued or requested certificates. It contains zero or more
subdirectories, each of which relates to a specific certificate. Each
subdirectory MUST be named after the Certificate ID.

Each certificate subdirectory MUST contain a file "url" which contains the URL
for the finalised order encoded in UTF-8. Clients MUST NOT include trailing
newlines or whitespace but SHOULD accept such whitespace and strip it.

NOTE: In previous versions of this specification (which targeted the draft ACME
protocol prior to the addition of orders), the URL contained in the "url" file
was the URL to the certificate. Such certificates may still exist in a state
directory; it is recommended that implementations be able to detect whether an
URL leads to a certificate or order via the Content-Type of the response
yielded when dereferencing the URL. These old certificate directories (and some
older new certificate directories) will also lack an "account" symlink.

Each certificate subdirectory MUST contain a relative symlink "account" to an
account directory used to request the certificate. (Old certificate directories
may lack this symlink.)

A client SHOULD automatically delete any certificate directory if the
certificate it contains is expired AND is not referenced by the "live"
directory. Certificates which have expired but are still referenced by the
"live" directory MUST NOT be deleted to avoid breaking reliant applications.

A certificate subdirectory MAY also contain information obtained from the "url"
file. If an ACME client finds only an "url" file, it MUST retrieve the
certificate information to ensure that local system services can make use of
the certificate:

  - If retrieval of the certificate fails with a permament error (e.g. 404), the
    certificate directory SHOULD be deleted.

  - If retrieval of the certificate fails with a temporary error (e.g. 202), the
    client tries again later. If provided, the Retry-After HTTP header should be
    consulted.

  - If retrieval of the certificate yields an `application/json` resource suggesting
    an order (rather than the certificate itself), it is parsed as an order to
    find the certificate URL. If the order is still in status "processing",
    handle it like a temporary error as above; if the order has somehow
    transitioned to "invalid", handle it like a permanent error as above.

  - If retrieval of the certificate succeeds, but the private key required to use
    it cannot be found, the certificate directory SHOULD be deleted.

After having successfully retrieved the certificate, the following files MUST
be written in the certificate subdirectory:

  - "cert": A file which MUST contain the PEM-encoded certificate.

  - "chain": A file which MUST contain the PEM-encoded certificate chain, i.e.
    the concatenation of the PEM encodings of all certificates but for the
    issued certificate itself and the root certificate which are necessary to
    validate the certificate. In other words, this contains any necessary
    intermediate certificates.

  - "fullchain": A file which MUST contain the concatenation of the "cert" and
    "chain" files.

  - "privkey": This MUST be a relative symlink to the privkey file of the
    private key used to create the certificate (i.e. a symlink pointing to
    `../../keys/(key ID)/privkey`).

### live

An ACME State Directory MUST contain a subdirectory "live". It contains zero or
more relative symlinks, each of which MUST link to a subdirectory of the
"certs" directory. The name of each symlink MUST be a hostname which is
expressed, or was previously expressed by one or more targets, followed by a
colon and the label of the target. If the label of the target is "", the colon
is omitted.

The "live" directory MUST point to the Most Preferred Certificate for each
target, as specified below.  Thus an application requiring a certificate for a
given hostname can unconditionally specify
`/var/lib/acme/live/example.com/{cert,privkey}` for the certificate, private
key, etc.

### tmp, Rules for State Directory Mutation

An ACME State Directory MUST contain a subdirectory "tmp" which is used for
storing temporary files. This directory is used instead of some system-scope
temporary directory to ensure that new files are created on the same filesystem
and thus can be atomically renamed to their desired final locations in the ACME
State Directory. For temporary files which do not require this, other temporary
directories may be more suitable.

**Any change to any object in the ACME State Directory MUST be one of the
following operations:**

  - An idempotent recursive directory creation ("mkdir -p").

  - Writing to a temporary file securely created with a high-entropy filename
    in "tmp" and appropriately locked, then either atomically moving it to its
    desired location in the ACME State Directory (potentially overwriting an
    existing file) or deleting it (e.g. in the event of an error before the
    file is completely written).

  - Securely creating a new symlink with a high-entropy filename in "tmp", then
    either atomically moving it to its desired location in the ACME State
    Directory (potentially overwriting an existing symlink) or deleting it.

  - Atomically deleting a file or recursively deleting a directory.

  - Idempotently changing file or directory permissions or ownership to conform
    with security requirements.

When an ACME client finds files in the "tmp" directory which it did not itself
open (in its current invocation), it SHOULD delete them. It SHOULD perform this
check whenever invoked.

Files MUST be created with the permissions they are to ultimately hold, not
have their permissions modified afterwards. Where particular permissions are
required of certain files, those permissions SHOULD be verified on every
invocation of the client. Where particular permissions are required of a
directory, those permissions MUST be verified before moving any file into that
directory. Note that because all files begin in the "tmp" directory, their
permissions MUST be strictly as strict or stricter than the permissions of any
direct or indirect parent directory, at least until the move is completed.

### Permissions (POSIX)

The following permissions on a State Directory MUST be enforced:

  - The "accounts", "keys" and "tmp" directories and all subdirectories within
    them MUST have mode 0770 or stricter. All files directly or ultimately
    within these directories MUST have mode 0660 or stricter, except for files
    in "tmp", which MUST have the permissions appropriate for their ultimate
    location before they are moved to that location.
 
  - For all other files and directories, appropriate permissions MUST be
    enforced as determined by the implementation. Generally this will mean
    directories having mode 0755 and files having mode 0644. Files and
    directories MUST NOT be world writable.

The ownership of a State Directory and all files and directories directly or
ultimately within it SHOULD be verified and enforced.

### Use of Symlinks

All symlinks used within the State Directory MUST be unbroken, MUST point to
locations within the State Directory and MUST be relatively expressed (i.e.,
they MUST NOT break if the State Directory were to be moved). Implementations
SHOULD verify these properties for any symlinks they encounter in the State
Directory.

Hooks
-----

It is desirable to provide extensibility in certain circumstances via the means
of hooks. These hooks are implemented using executable shell scripts or
binaries external to an implementation. Several types of hook are defined.

All hooks are kept in a separate directory, the ACME Hooks Directory. The
RECOMMENDED path is `/usr/lib/acme/hooks`, except for systems which use
`/usr/libexec`, which SHOULD use `/usr/libexec/acme/hooks`.

The hooks directory MUST contain only executable objects (i.e. executable
scripts or binaries or symlinks to them). However, implementations SHOULD
ignore non-executable objects. "Executable" here means executable in practical
terms, and does not refer merely to the file having the executable bits set in
its mode, which is a necessary but not sufficient condition.

### Calling Convention

An ACME client MUST invoke hooks as follows: Take the list of objects in
the hooks directory and sort them in ascending lexicographical order
by filename. Execute each object in that order. If execution of an object
fails, execution of subsequent objects MUST continue.

The first argument when invoking a hook is always the event type causing
invocation of the hook.

When invoking a hook, the environment variable `ACME_STATE_DIR` MUST be set to
the absolute path of the State Directory.

A hook is invoked successfully if it exits with exit code 0. A hook which exits
with exit code 42 indicates a lack of support for the event type. Any other
exit code indicates an error.

### sudo Protocol

It may be desirable for an implementation to run as an unprivileged user. In
this case, it is necessary to have some way to elevate notification hooks
so they can perform privileged operations such as restarting system services.
Since most POSIX systems do not support the setuid bit on scripts, the use
of "sudo" is suggested.

When an implementation is not running as root, and executes a hook, and that
hook is owned by root, and it has the setuid bit set, and the OS does not (as
currently configured) support setuid on scripts, and the "sudo" command is
available, and the file begins with the characters "#!", execute "sudo -n --
FILE EVENT-TYPE ARGS...", where FILE is the absolute path to the file and ARGS
are dictated by hook event type. Success is not guaranteed as the system
administrator must have configured the sudoers file to allow this operation.

### live-updated

The "live-updated" hook is invoked when one or more symlinks in the "live"
directory are created or updated. There are no arguments.

Each object invoked MUST have passed to stdin a list of the names of the
symlinks in the "live" directory which have changed target, i.e. the hostnames
for which the preferred certificate has changed. The hostnames are separated by
newlines, and the final hostname also ends with a newline.

### challenge-http-start, challenge-http-stop

These hooks are invoked when an HTTP challenge attempt begins and ends.
They can be used to install challenge files at arbitrary locations.

The first argument is the hostname to which the challenge relates.

The second argument is the filename of the target file causing the challenge to
be completed. This may be the empty string in some circumstances; for example,
when an authorization is being obtained for the purposes of performing
revocation rather than for obtaining a certificate.

The third argument is the filename which must be provisioned under
`/.well-known/acme-challenge/`.

The required contents of the file is passed as stdin.

A hook should exit with exit code 0 only if it successfully installs or removes
the challenge file. For `challenge-http-start`, an implementation may consider
such an exit to authoritatively indicate that it is now feasible to complete
the challenge.

Example call:

```sh
echo evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ | \
ACME_STATE_DIR=/var/lib/acme /usr/lib/acme/hooks/foo \
  challenge-http-start example.com some-target-file \
  evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA
```

### challenge-tls-sni-start, challenge-tls-sni-stop

These hooks are invoked when a TLS-SNI challenge begins and ends. They can be
used to install the necessary validation certificate by arbitrary means.

The hook MUST return 0 only if it succeeds at provisioning/deprovisioning the
challenge. When returning 0 in the `challenge-tls-sni-start` case, it MUST
return only once the certificate is globally visible.

The first argument is the hostname to which the challenge relates.

The second argument is the filename of the target file causing the challenge to
be completed. This may be the empty string in some circumstances; for example,
when an authorization is being obtained for the purposes of performing
revocation rather than for obtaining a certificate.

The third argument is the hostname which will be specified via SNI when the
validation server checks for the certificate.

The fourth argument is an additional hostname which must appear in the certificate.
Both hostnames must appear as dNSName SubjectAlternateNames in the certificate returned.

The third and fourth argument may be equal in some cases.

A PEM-encoded certificate followed by a PEM-encoded private key is fed on
stdin. A hook can choose to provision this certificate to satisfy the
challenge. It can also construct its own certificate.

### challenge-dns-start, challenge-dns-stop

These hooks are invoked when a DNS challenge begins and ends. They can be used
to install the necessary validation DNS records, for example via DNS UPDATE.

The hook MUST return 0 only if it succeeds at provisioning/deprovisioning the
challenge. When returning 0 in the `challenge-dns-start` case, it MUST return
only once the record to be provisioned is globally visible at all of the
authoritative nameservers for the applicable zone. The hook is not required to
consider the effects of caching resolvers as ACME servers will perform the
lookup directly.

The first argument is the hostname to which the challenge relates.

The second argument is the filename of the target file causing the challenge to
be completed. This may be the empty string in some circumstances; for example,
when an authorization is being obtained for the purposes of performing
revocation rather than for obtaining a certificate.

The third argument is the value of the DNS TXT record to be provisioned.

Note that as per the ACME specification, the TXT record must be provisioned at
`_acme-challenge.HOSTNAME`, where HOSTNAME is the hostname given.

Example call:

```sh
ACME_STATE_DIR=/var/lib/acme /usr/lib/acme/hooks/foo \
  challenge-dns-start example.com some-target-file \
  evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA
```


SRV-ID
------

The desire for a certificate containing a SRV-ID subjectAltName is expressed by
placing a file in the "desired" directory named after the SRV-ID, e.g.
"\_xmpp-client.example.com". This is recognised as a SRV-ID automatically by
virtue of it starting with an underscore. Since hostnames may not contain
underscores, this is not ambiguous.

Support for SRV-ID in ACME implementations remains to be seen.

Operations
----------

### Conform

To conform a State Directory means to examine everything in the directory for
consistency and validity. Permissions are changed as necessary to ensure they
match the implementation's policy. The implementation verifies that all
symlinks are unbroken, relative and point to locations within the State
Directory. Remnant temporary files are deleted. Errors are indicated for any
malformed directory (e.g. account directory with no private key, etc.)

This operation is idempotent.

### Reconcile

A certificate can be described as "satisfying" a target, or as being the Most
Preferred Certificate for a target. These are distinct classifications, and
neither implies the other. A certificate might be the Most Preferred
Certificate for a target even though it does not satisfy it, because it is the
"least worst option". A certificate might satisfy a target but not be the Most
Preferred Certificate for it.

The reconcile operation is the actual act of “building” the State Directory.

  - Begin by performing the Conform operation.

  - If there are any uncached certificates (certificate directories containing
    only an "url" file), cache them, waiting for them to become available
    (orders to finish processing, etc.) if necessary.

  - If there are any certificates marked for revocation (meaning that a
    "revoke" file exists in the certificate directory), but which are not
    marked as being revoked (meaning that a "revoked" file exists in the
    certificate directory), request revocation of the certificate and, having
    obtained confirmation of that revocation, create an empty file "revoked" in
    the certificate directory.

  - For each target, satisfy that target.

    To satisfy a target:

    - If there exists a certificate satisfying the target, the target is
      satisfied. Done.

    - Otherwise, request a certificate with the hostnames listed under the
      "request" section of the target. If a certificate cannot be obtained,
      fail. Satisfy the target again.

      When making certificate requests, use the provider/account information
      specified in the "request" section.

    To request a certificate:

    - Create an order with the necessary identifiers and satisfy the
      authorizations specified within the newly created order. If the order
      becomes invalid due to a failed authorization, create another order and
      start again, until an order's authorization requirements are successfully
      fulfilled or it is determined that no further forward progress can be
      made regarding one or more authorizations.

    - Having obtained an order with status "ready", form an appropriate CSR
      containing the SANs specified in the "request" section of the applicable
      target and finalise the order. Write the order URL to the State
      Directory; there is no need to wait for it to exit the "processing"
      state.

- Update the "live" directory as follows:

    - For each (hostname, target) pair in the Hostname-Target Mapping, create a
      symlink for the hostname pointing to the Most Preferred Certificate for
      the target, if one exists.

- If any certificates were requested while satisfying targets, perform the
  Reconcile operation again; stop.

- Optionally perform cleanup operations:

    - Delete the certificate directories for any cullable certificates.

    - Delete (optionally, securely erase) the key directories for any cullable
      private keys.

This operation is idempotent.

**Satisfying targets.** A certifigate satisfies a target if:

  - the private key for the certificate is available in the State Directory, and
  - the certificate is not known to be revoked, and
  - all stipulations listed in the "satisfy" section of the target are met:

      - the "names" stipulation is met if the dNSName SANs in a given
        certificate are a superset of the names specified.

    and
  - the certificate is not self-signed, and
  - the current time lies between the Not Before and Not After times, and
  - the certificate is not near expiry.

**Near expiry.** A certificate is near expiry if the difference between the
current time and the "Not After" time is less than some implementation-specific
threshold. The RECOMMENDED threshold is 30 days or 33% of the validity period,
whichever is lower.

**Most Preferred Certificate.** The Most Preferred Certificate for a given
target is determined as follows:

  - Certificates which satisfy the target are preferred over certificates that
    do not satisfy the target.

  - For two certficates neither of which satisfies the target, one is
    preferred over the other if the first criterion in the list of the
    criteria for satisfying a target which it does not satisfy is later in
    the list of criteria than for the other.

    For example, a revoked certificate for which a private key is available
    is preferred over a certificate for which no private key is available. A
    self-signed certificate with the right names is preferred over a self or
    CA-signed certificate with the wrong names. A self-signed certificate is
    preferred over a revoked certificate. (A revoked certificate may not be
    exemptible by a user; thus even a self-signed certificate is preferable
    to a certificate known to be revoked.)

  - Certificates with later "Not After" times are preferred.

**Cullability.** A certificate is cullable if:

  - it is expired, and
  - after reconcilation, it is unreferenced by any "live" symlink.

A private key is cullable if:

  - it does not relate to any known certificate, and
  - it was not recently created or imported. The definition of "recently" is
    implementation-specific.

### Revocation

A certificate is revoked by creating an empty file "revoke" in the certificate
directory and reconciling.

Identifiers
-----------

Accounts, keys and certificates are stored in directories named by their
identifiers. Their identifiers are calculated as follows:

**Key ID:** Lowercase base32 encoding with padding stripped of the SHA256 hash
of the subjectPublicKeyInfo constructed from the private key.

**Account ID:** Take the Directory URL for the ACME server. Take the hostname,
port (if applicable) and path, stripping the scheme (e.g.
"example.com/directory"). If the path is "/", strip it ("example.com/" becomes
"example.com"). URL-encode this string so that any slashes are percent-encoded
using lowercase hexadecimal. Take this string and append "/" followed by the
string formed by calculating a Key ID using the account's private key.

  e.g. `example.com%2fdirectory/irq7564p5siu3zngnc2caqygp3v53dfmh6idwtpyfkxojssqglta`

Each account directory is thus an account key-specific subdirectory of the
string formed from the directory URL.

For production use the scheme MUST be "https". In some cases, it may be desirable
to test using HTTP. Where an HTTP URL is specified, it is prefixed with `http:`. For example:

  `http:example.com%2fdirectory/irq7564p5siu3zngnc2caqygp3v53dfmh6idwtpyfkxojssqglta`

**Certificate ID:** A certificate ID must be assignable before a certificate
has been issued, when only the public key and order URL are known.

Thus, the Certificate ID shall be the lowercase base32 encoding with padding
stripped of the SHA256 hash of the order URL (or, for legacy certificates, the
certificate URL).

A certificate directory is invalid if the "url" file does not match the
Certificate ID. Such a directory should be deleted.

Temporary Use of Self-Signed Certificates
-----------------------------------------

Some daemons may fail terminally when a certificate file referenced by their
configuration is not present. Thus, where a client is unable to procure a
certificate immediately, it MAY choose to provision a self-signed certificate
referenced by symlinks under 'live' instead. This will allow a daemon to
continue operating (perhaps serving non-TLS requests or requests for other
hostnames) with reduced functionality.

If a client uses such interim self-signed certificates, it MUST create an empty
'selfsigned' file in the certificate directory to indicate that the certificate
is a self-signed certificate. The 'url' file MUST NOT exist. The 'cert' and
'fullchain' files MUST be identical, and the 'chain' file MUST exist and MUST
be an empty file.

The self-signed certificate MAY contain information in it which points out the
configuration issue the certificate poses, e.g. by placing a short description
of the problem in the O and OU fields, e.g.:

  OU=ACME Cannot Acquire Certificate
  O=ACME Failure Please Check Server Logs

The Certificate ID of a self-signed certificate is the string "selfsigned-"
followed by the lowercase base32 encoding with padding stripped of the SHA256
hash of the DER encoded certificate.
