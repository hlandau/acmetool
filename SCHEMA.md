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
        (certificate ID)/
          cert              ; Contains the certificate
          chain             ; Contains the necessary chaining certificates
          fullchain         ; Contains the certificate and the necessary chaining certificates
          privkey           ; Symlink to a key privkey file
          url               ; URL of the certificate

      keys/
        (key ID)/
          privkey           ; PEM-encoded certificate private key

      accounts/
        (account ID)/
          privkey           ; PEM-encoded account private key
          authorizations/
            (domain)/
              expiry        ; File containing RFC 3336 expiry timestamp
              url           ; URL of the authorization (optional)

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

Each target has one or more hostnames associated with it. The file is a YAML
file with the following schema:

    names:
      (list of strings, one per hostname)
    provider: (URL of ACME server)
    priority: (integer, defaults to zero)

If `names` is not specified, the target expresses a single name, which is the
filename of the file. If that name is not a valid hostname, or if the file
explicitly specifies zero names, the target is invalid.

If `provider` is not specified, an implementation-specific default ACME server
URL is used. 

Wildcard certificates, if ACME ever supports them, may be indicated just as
they would be in a certificate. For example, an empty file named
`*.example.com` could be created in the desired directory.

The function of an implementation of this specification is simply this: to
ensure that currently valid certificates are always provisioned which provide
for all hostnames expressed across all targets.

The lumping of hostnames into different target files controls when separate
certificates are issued, and when single certificates with multiple SANs are
issued. For example, creating two empty files, `example.com` and
`www.example.com`, would result in two certificates. Creating a single file
`example.com` with the following contents would result in one certificate with
both names:

  names:
    - example.com
    - www.example.com

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

#### authorizations

An ACME client MAY keep track of unexpired ACME authorizations it has obtained
from a provider in order to avoid unnecessarily rerequesting authorizations. It
does this by maintaining a directory "authorizations" underneath a given
account directory. Each directory in this directory represents a hostname. Each
such directory MAY contain the following files:

  - "expiry", a file containing an RFC 3336 timestamp representing the expiry
    time of the authorization.

  - "url", a file containing the URL of the authorization.

An authorization is deemed valid and useable for the purposes of requesting a
certificate only if it has an "expiry" file expressing a point in time in the
future.

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
for the certificate encoded in UTF-8. Clients MUST NOT include trailing
newlines or whitespace but SHOULD accept such whitespace and strip it.

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

  - "fullchain": A file which MUST contains the concatenation of the "cert" and
    "chain" files.

  - "privkey": This MUST be a relative symlink to the privkey file of the
    private key used to create the certificate (i.e. a symlink pointing to
    `../../keys/(key ID)/privkey`).

### live

An ACME State Directory MUST contain a subdirectory "live". It contains zero or
more relative symlinks, each of which MUST link to a subdirectory of the
"certs" directory. The name of each symlink MUST be a hostname which is
expressed, or was previously expressed by one or more targets.

The "live" directory MUST point to the preferred certificate for each each
hostname.  Thus an application requiring a certificate for a given hostname can
unconditionally specify `/var/lib/acme/live/example.com/{cert,privkey}` for the
certificate, private key, etc.

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

  - Changing file or directory permissions or ownership to conform with
    security requirements.

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

Notification Hooks
------------------

It is desirable for system services to be able to be notified when the
certificate pointed to by a symlink in the "live" directory has changed. This
is realised using a separate directory, the ACME Hooks Directory.

On UNIX-like systems, this directory SHOULD be "/usr/lib/acme/hooks", except
for systems which use "/usr/libexec", which SHOULD use
"/usr/libexec/acme/hooks".

The hooks directory MUST contain only executable objects (i.e. executable files
or symlinks to them).

An ACME client SHOULD invoke notification hooks whenever it has updated a
symlink in the "live" directory.

An ACME client MUST invoke the notification hooks as follows: Take the list of
objects in the hooks directory and sort them in ascending lexicographical
order. Execute each object in that order. If execution of an object fails, execution
of subsequent objects MUST continue.

Each object invoked MUST have the following command line arguments passed:

  - The first command line argument shall be the string "live-updated".

  - The second command line argument shall be the name of the symlink in the
    "live" directory which has changed its target, i.e. the hostname the
    preferred certificate of which has changed.

The following environment variable MUST be set for the purposes of the invocation:

  - "ACME\_STATE\_DIR" shall be set to the absolute path of the State Directory.

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

To conform a state directory means to evaluate everything in it and delete any
account subdirectory, certificate subdirectory, key subdirectory or symlink
inside the live directory which is not valid as described above.

Delete any files in the "tmp" directory.

### Reconcile

To perform the Reconcile operation, first perform the Conform operation.

From the "desired" hostname/service label set, form clusters. Determine a list of
clusters which doesn't have retrieved, CA-signed certificates with known private keys
expiring in more than 30 days or 33% of the validity period, whichever is lower.
During this process, download any undownloaded certificates.

For all such clusters, attempt to obtain certificates using the appropriate policy:

  The endpoint URL is specified by the policy or inherited from defaults.  If
  there is no account key for that URL, create a new account key. Ensure the
  registration exists.

  Obtain authorizations for every hostname required. Where an unexpired
  authorization is listed as being present under the account directory, this can
  be skipped, but if issuance fails due to the absence of an authorization, that
  authorization directory is deleted and an authorization is obtained.

  Form a CSR containing all SANs required by the cluster and submit the CSR.
  Save the certificate URL.
  
If any certificates were requested, perform the Reconcile operation again.

Identifiers
-----------

Accounts, keys and certificates are stored in directories named by their
identifiers. Their identifiers are calculated as follows:

**Key ID:** Lowercase base32 encoding with padding stripped of the SHA256 hash
of the subjectPublicKeyInfo constructed from the private key.

**Account ID:** Take the Directory URL for the ACME server. Take the hostname,
port (if applicable) and path, stripping the scheme, which must be HTTPS (e.g.
"example.com/directory"). If the path is "/", strip it ("example.com/" becomes
"example.com"). URL-encode this string so that any slashes are percent-encoded
using lowercase hexadecimal. Take this string and append "/" followed by the
string formed by calculating a Key ID using the account's private key.

  e.g. "example.com%2fdirectory/irq7564p5siu3zngnc2caqygp3v53dfmh6idwtpyfkxojssqglta"

Each account directory is thus an account key-specific subdirectory of the
string formed from the directory URL.

**Certificate ID:** A certificate ID must be assignable before a certificate
has been issued, when only the public key and certificate URL are known.

Thus, the Certificate ID shall be the lowercase base32 encoding with padding
stripped of the SHA256 hash of the certificate URL.

A certificate directory is invalid if the "url" file does not match the
Certificate ID. In this case it should be treated as though the certificate
is expired; the directory should be deleted unless it is referenced by a symlink
in 'live'.

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
is a self-signed certificate. The 'url' file MUST NOT exist. The "cert" and
"fullchain" files MUST be identical, and the "chain" file MUST exist and MUST
be an empty file.

The self-signed certificate MAY contain information in it which points out the
configuration issue the certificate poses, e.g. by placing a short description
of the problem in the O and OU fields, e.g.:

  OU=ACME Cannot Acquire Certificate
  O=ACME Failure Please Check Server Logs

The Certificate ID of a self-signed certificate is the string "selfsigned-"
followed by the lowercase base32 encoding with padding stripped of the SHA256
hash of the DER encoded certificate.
