Rootless support
================

acmetool has experimental support for root-free operation.

In order to run root-free, after installing acmetool in `/usr/local/bin` (or
wherever you want it), before running acmetool, do the following:

- Create a new user `acme` <small>(or whatever you want)</small>.

- Create the directory `/var/lib/acme` and change the owning user and group to
  `acme`. <small>(You can use a different directory, but you must then make sure you
  pass `--state PATH` to all invocations of acmetool.)</small>

- Create the directory `/usr/lib/acme/hooks` <small>(`/usr/libexec/acme/hooks` on
  distros which use libexec)</small>.  Make it writable by `acme` for the time being by
  changing the group to `acme` and making the directory group-writable. (You
  can make this read-only after running the quickstart process, which places
  some shell scripts in here to reload servers. You can audit these scripts
  yourself or use your own if you wish.)

- Change to the user `acme` and run `acmetool quickstart`.

    $ sudo -u acme acmetool quickstart

  A crontab will be installed automatically as the `acme` user; you may wish to
  examine it.

- As root, make the `hooks` directory root-owned/not group writable once more.
  Ensure that the scripts are root-owned:

    # chown -R root:root /usr/lib*/acme/hooks
    # chmod 755 /usr/lib*/acme/hooks

  Inspect the hook scripts if you wish. Mark the hook scripts setuid:

    # chmod u+s /usr/lib*/acme/hooks/*

  UNIX systems don't support setuid shell scripts, so this bit is ignored.
  Rather, acmetool takes it as a flag to tell it to run these scripts via
  `sudo`. This is necessary so that web servers, etc. can be reloaded.

  The conditions for running using `sudo` are that the files have the setuid
  bit set, that they be owned be root, that they be scripts and not binaries,
  and that acmetool is not being run as root.

- Setup sudo. You will need to edit the sudoers file so that the hook scripts
  (which you have inspected and trust) can be executed by acmetool. It is
  essential that these have the `NOPASSWD` flag as the scripts must be executable
  noninteractively.

  `# visudo`

  Add the line:

  `acme ALL=(root) NOPASSWD: /usr/.../acme/hooks/`

  Replace `...` above with `lib` or `libexec` as appropriate.

- Setup your challenge method:

  **Webroot:** Make sure the `acme` user can write to the webroot directory you
  configured.

  **Redirector:** Make sure the directory `/var/run/acme/acme-challenge` is
  writable by the `acme` user. `acmetool` puts challenges here because the
  redirector looks here (internally it's a glorified webroot mode).

  Note that `/var/run` will be a tmpfs on many modern OSes, so the directory
  ceases to exist on reboots. The redirector will try to create the directory
  (as user root, mode 0755) if it doesn't exist. This happens before the
  redirector drops privileges from root. (It has to run as root initially to
  bind to port 80.)

  A configuration option has been added to make the redirector ensure that
  the directory is writable by a certain group when starting up. When this
  option is used, mode 0775 is used instead and the group owner is changed
  to a given GID.

  Pass `--challenge-gid=GID` to `acmetool redirector` (edit your service
  manager's configuration, e.g. the systemd unit file), where GID is the
  numeric group ID of the group owner for the challenge directory (i.e. the GID
  of the `acme` group). (Group names rather than IDs may be supported on some
  platforms, but this is not guaranteed and will vary. Use of a GID is
  recommended.)

  **Proxy:** If you are using the proxy method, you won't be able to listen on
  port 402 as a non-root user. Use port 4402 instead, which acmetool will try
  to use instead.

  **Listener:** Not usable under non-root operation, as it would not be able
  to bind to ports 80/443. But this is not really relevant as this mode is
  not useful for anything other than development anyway.
