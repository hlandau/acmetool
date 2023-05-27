(define-module (dd-acmetool))
(use-modules (dedoc))

;; Outline                                                                 {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define-public (top)
  (doc
    (docctl
      (title "acmetool User Manual"))
    (docbody
      (user-guide)
      (man-pages)
      (acme-state-storage-specification)
      )))

;; User Guide                                                              {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (user-guide)
  (sec "User's Guide"
     (with-id 'intro (sec "Introduction & Design Philosophy"
          (p "acmetool is an easy-to-use command line tool for automatically acquiring TLS certificates from ACME servers such as Let's Encrypt, designed to flexibly integrate into your webserver setup to enable automatic verification.")
          (p "acmetool features:")
          (dict
            (dice (dick "Non-interference")
                  (dicb (p "Unlike the official Let's Encrypt client, this doesn't modify your web server configuration.")))
            (dice (dick "Target-oriented and idempotent")
                  (dicb (p "acmetool is designed to work like “make”: you specify what certificates you want, and acmetool obtains certificates as necessary to satisfy those requirements. If the requirements are already satisfied, acmetool doesn't do anything when invoked. Thus, acmetool is ideally suited for use on a cron job; it will do nothing until the certificates are near expiry, and then obtain new ones.")))
            (dice (dick "Clear and minimal state")
                  (dicb (p "acmetool is designed to minimise the use of state and be transparent in the state that it does use. All state, including certificates, is stored in a single directory, by default "(tt "/var/lib/acme")". The schema for this directory is simple, comprehensible and documented TODO.")))
            (dice (dick "Stable filenames")
                  (dicb (p "The certificate for a given hostname "(tt "example.com")" always lives at "(tt "/var/lib/acme/live/example.com/{cert,chain,privkey}")". This is a symlink to the real certificate directory and gets changed as certificates are renewed.")))
            (dice (dick "Fully automatic renewal")
                  (dicb (p "acmetool can automatically reload your webserver when it changes the target of a "(tt "live")" symlink. In conjunction with acmetool's use of stable filenames and idempotent design, this means that renewal can be fully automatic.")))
            (dice (dick "Flexible validation methods")
                  (dicb (p "acmetool supports six different validation methods:")
                        (dict
                          (dice (dick "Webroot")
                                (dicb (p "acmetool places challenge files in a given directory, allowing your normal web server to serve them. You must ensure the directory is served at "(tt "/.well-known/acme-challenge/")".")))
                          (dice (dick "Proxy")
                                (dicb (p "When acmetool needs to validate for a domain, it temporarily spins up a built-in web server on port 402 or 4402 (if being used under the non-root validation mode). You configure your web server to proxy requests for "(tt "/.well-known/acme-challenge/")" to this server at the same path.")))
                          (dice (dick "Stateless")
                                (dicb (p "TODO REVALIDATE")))
                          (dice (dick "Redirector")
                                (dicb (p "If the only thing you want to do with port 80 is redirect people to port 443, you can use acmetool's built in redirector HTTP server. You must ensure that your existing web server does not listen on port 80. acmetool redirects requests to HTTPS, but its control of port 80 ensures it can complete validation.")))
                          (dice (dick "Listen")
                                (dicb (p "Listen on port 80 or 443 to respond to challenges. This is only really useful for development purposes, or if you are securing services other than web servers and not running anything on port 80 or 443.")))
                          (dice (dick "Hook")
                                (dicb (p "You can write custom shell scripts or binary executables which acmetool invokes to provision challenges at the desired location. The mechanism of operation of such hook scripts can be arbitrary."))))))
            (dice (dick "Non-root operation")
                  (dicb (p "If you don't want to trust acmetool, you can setup acmetool to operate without running as root. If you don't have root access to a system, you may still be able to use acmetool by configuring it to use a local directory and webroot mode.")))
            (dice (dick "Designed for automation")
                  (dicb (p "acmetool is designed to be fully automatable. Response files allow you to run the quickstart wizard automatically.")))
          )))
     (sec "Installation"
          (p "You can install acmetool by building from source or TODO. Both are easy.")
          (dict
            (dice (dick "Installing: using binary releases")
                  (dicb (p "TODO")))
            (dice (dick "Installing: Ubuntu users")
                  (dicb (p "TODO")))
            (dice (dick "Installing: Debian users")
                  (dicb (p "TODO")))
            (dice (dick "Installing: RPM-based distros")
                  (dicb (p "TODO")))
            (dice (dick "Installing: Arch Linux users")
                  (dicb (p "TODO")))
            (dice (dick "Installing: Alpine Linux users")
                  (dicb (p "TODO")))
            (dice (dick "Installing: from source")
                  (dicb
                    (p "TODO")
                    ))
            (dice (dick "Installing: from source (existing GOPATH)")
                  (dicb (p "The Makefile is intended to make things easy for users unfamiliar with Go packaging conventions. If you know what a GOPATH is and have one set up, you can and should instead simply do:")
                        (listing "\
$ git config --global http.followRedirects true
$ go get -u github.com/hlandau/acmetool
$ sudo cp $GOPATH/bin/acmetool /usr/local/bin/acmetool")
                        (p "Note: Although use of cgo is recommended, building without cgo is supported.")
                        ))))

     (sec "After installation"
          (sec "Initial configuration"
               (p "Having installed acmetool, run the quickstart wizard for a guided setup. You may wish to ensure you have "(tt "dialog")" in your PATH, but acmetool will fallback to basic stdio prompts if it's not available.")
               (listing "$ sudo acmetool quickstart")
               (p "If you don't want to run acmetool as root, see the non-root setup guide TODO.")
               (p "Pass "(tt "--expert")" to quickstart if you want to choose what key parameters to use (RSA or ECDSA, RSA key size, ECDSA curve). By default 2048-bit RSA is used.")
               (p "If you want to automate the quickstart process, see the section on response files below.")
               (p "It is safe to rerun quickstart at any time."))
          (sec "Configuring your web server"
               (p "Once you've completed the quickstart, you should configure your web server as necessary to enable validation. See the Web server configuration TODO section below."))
          (sec "Obtaining certificates"
               (p "Once everything's ready, simply run:")
               (listing "$ sudo acmetool want example.com www.example.com")
               (p "This adds a target desiring a certificate for hostnames "(tt "example.com")" and "(tt "www.example.com")". You can specify as many hostnames (SANs) as you like. Whenever you run acmetool in the future, it'll make sure that a certificate for these hostnames is available and not soon to expire.")
               (p "acmetool lumps hostnames together in the same certificate. If you want "(tt "example.com")" and "(tt "www.example.com")" to be separate certificates, use separate "(tt "want")" commands to configure them as separate targets:")
               (listing "$ sudo acmetool want example.com\n$ sudo acmetool want www.example.com")
               (p "If all went well, your certificate should be available at "(tt "/var/lib/acme/live/example.com")". This is a directory containing PEM files "(tt "cert")", "(tt "chain")", "(tt "fullchain")" and "(tt "privkey")". The use of these files varies by application; typically you will use only a subset of these files."))
          (sec "Troubleshooting"
               (p "If all didn't go well, you might find it helpful to run with debug logging:")
               (listing "$ sudo acmetool --xlog.severity=debug")
               (p "(There's no need to run "(tt "want")" again; the targets are recorded even if reconciliation is not successful.)"))

          (sec "Auto-renewal: cron jobs"
               (p "acmetool offers to install a cronjob during the quickstart process. This simply runs "(tt "acmetool --batch")", which will idempotently ensure that all configured targets are satisfied by certificates not soon to expire. ("(tt "--batch")" here ensures that acmetool doesn't try to ask any questions.)"))

          (sec "Auto-renewal: reloading your webserver"
               (p "When acmetool refreshes a certificate, it changes the symlink in "(tt "live")" and executes hook scripts to reload your web sserver or do whatever you want. Specifically, it executes any executable files in "(tt "/usr/lib/acme/hooks")" (or "(tt "/usr/libexec/acme/hooks")" if on a distro that uses libexec). You can drop your own executable files here, and acmetool will invoke them when it changes certificates. (For information on the calling convention, see TODO.)")
               (p (tt "acmetool quickstart")" installs some default hooks applicable to common webservers. These hooks are shell scripts which contain the string "(tt "#!acmetool-managed!#")". acmetool reserves the right to overwrite any file containing this string with a newer version of the script, in the event that the default scripts are updated in subsequent versions of acmetool. If you make changes to a default script and do not wish them to be overwritten, you should remove this line to ensure that your changes are not overwritten. However, note that the default hook scripts are designed to be configurable and it will be rare that you need to modify the scripts themselves. If you encounter a situation where you need to change the script itself, you may consider whether it would be appropriate to file an enhancement request. The string "(tt "#!acmetool-managed!#")" must be present near the start of the file in order to be detected.")
               (p "If you want to disable a default hook entirely, you should replace it with an empty file rather than deleting it, as "(tt "acmetool quickstart")" will automatically install absent default hooks."))

          (sec "Default hook scripts: the “reload” hook"
               (p "The reload hook is a default hook installed by "(tt "acmetool quickstart")". It reloads a list of services using commands specific to the distro. The correct command is detected automatically; "(tt "service $SERVICE reload")", "(tt "systemctl reload $SERVICE")", and "(tt "/etc/init.d/$SERVICE reload")" are supported.")

               (p "A default list of services is provided which includes the most common webserver service names. This list can be customised using the "(tt "reload")" hook configuration file.")

               (p "The "(tt "reload")" hook configuration file is located at "(tt "/etc/conf.d/acme-reload")" or "(tt "/etc/default/acme-reload")"; the correct path depends on the conventions of your distro. It is a sourced shell file which can modify the default configuration variables of the "(tt "reload")" script. Currently, the only variable is the "(tt "SERVICES")" variable, a space-separated list of service names.")
               (p "You can overwrite the services list outright, or append to it like so:")
               (listing "# Example reload hook configuration file adding a service to the list of\n# services to be restarted.\nSERVICES=\"$SERVICES cherokee\""))

          (sec "Default hook scripts: the “haproxy” hook"
               (p "The haproxy hook is a default hook which "(tt "acmetool quickstart")" can optionally install. It only offers to install this hook if HAProxy is detected as being installed
                   on the system.")
               (p "HAProxy is rather bizarre in its TLS configuration requirements; it requires certificates and private key to be appended together in the same file. acmetool does not support this natively and is unikely ever to as a default configuration for security reasons. Instead, the "(tt "haproxy")" hook creates the necessary files for HAProxy from the certificate and private key files whenever they are updated. Thus, additional copies of the private key are only made when necessary to support HAProxy."))
          (sec "Inside the state directory"
               (p "acmetool aims to minimise use of state and be transparent about the state it does keep. When you run "(tt "acmetool want")", acmetool does these things:")
               (ul
                 (li (p "It configures a new target by writing a YAML file to "(tt "/var/lib/acme/desired/")" describing the desired hostnames."))
                 (li (p "It runs the default command, "(tt "reconcile")", to ensure that all targets are met.")))
               (p "To demonstrate, you can replicate the function of "(tt "acmetool want")":")
               (listing "$ sudo touch /var/lib/acme/desired/example.com\n$ sudo acmetool")
               (p "Target files live in the "(tt "desired")" directory. An mepty target file defaults to its filename as the target hostname.")
               (p "More information on the format of the acmetool state directory and target files. TODO")))

     (sec "Web server configuration: challenges"
          (sec "Redirector mode"
               (p "No configuration required, but ensure that your web server is not listening on port 80 and that the redirector service ("(tt "acmetool redirector --service.daemon --service.uid=<uid-to-drop-privileges-to>")") is started."))
          (sec "Proxy mode: nginx/tengine"
               (p "You can configure nginx/tengine for use with acmetool in proxy mode as follows:")
               (listing "\
http {
  server {
    ... your configuration for port 80 ...
    location /.well-known/acme-challenge/ {
      proxy_pass http://acmetool;
    }
  }
  upstream acmetool {
    # (Change to port 4402 if using non-root mode.)
    server 127.0.0.1:402;
  }
}"))
          (sec "Proxy mode: Apache httpd"
               (listing "\
# (Change to port 4402 if using non-root mode.)
ProxyPass \"/.well-known/acme-challenge\" \"http://127.0.0.1:402/.well-known/acme-challenge\"")
               (p "Ensure you load "(tt "mod_proxy")" and "(tt "mod_proxy_http")"."))

          (sec "Proxy mode: changing port"
               (p "If you need to change the ports on which acmetool listens, see the "(tt "request: challenge: http-ports")" directive. See State storage schema TODO."))

          (sec "Webroot mode"
               (p "If you don't have a particular webroot path in mind, consider using "(tt "/var/run/acme/acme-challenge")" as a recommended standard. acmetool defaults to this as a webroot path if you don't explicitly configure one. (See “Challenge Completion Philosophy” below.)"))

          (sec "Webroot mode: nginx/tengine"
               (listing "\
http {
  server {
    ... your configuration for port 80 ...
    location /.well-known/acme-challenge/ {
      alias /var/run/acme/acme-challenge/;
    }
  }
}")
              (p "Note that the configuration will need to be repeated for each vhost. You may wish to avoid duplication by placing the applicable configuration in a separate file and including it in each vhost."))

          (sec "Webroot mode: Apache httpd"
               (listing "\
Alias \"/.well-known/acme-challenge/\" \"/var/run/acme/acme-challenge/\"
<Directory \"/var/run/acme/acme-challenge\">
  AllowOverride None
  Options None

  # If using Apache 2.4+
  Require all granted

  # If using Apache 2.2 or older
  Order allow, deny
  Allow from all
</Directory>"))

            (sec "Hook mode"
                 (p "See Challenge Hooks TODO."))

            (sec "Stateless mode"
                 (p "TODO"))

            (sec "Stateless mode: nginx/tengine"
                 (p "TODO"))

            (sec "Stateless mode: Apache"
                 (p "TODO"))

          )
     (sec "Web server configuration: TLS"
          (p "Mozilla has a TLS configuration generator TODO that you can use to generate configuration for common web servers."))

     (sec "Challenge completion philosophy"
          (p "acmetool's philosophy to completing challenges is to try absolutely anything that might work. So long as "(em "something")" works, acmetool doesn't care what it was that worked. When "(tt "acmetool quickstart")" asks you what method to use, this is asked purely to determine a) whether to ask you for a webroot path (if you selected webroot mode) and b) whether to ask you if you want to install the redirector service (if you selected redirector mode and are using systemd, for which automatic service installation is supported). It doesn't determine what strategies acmetool does or doesn't use, so it's normal to see log output relating to a failure to use methods other than the one you chose.")
          (p "acmetool always tries to listen on port 402 and 4402 when completing challenges, in case something proxies to it. It always tries to listen on ports 80 and 443, in case you're not running a webserver yet. And it always tries to place challenge files in any webroot paths you have configured. Finally, it always tries to place challenge files in "(tt "/var/run/acme/acme-challenge")"; this serves as a standard location for challenge files, and the redirector daemon works by looking here.")
          (p "Failure to complete any of these efforts is non-fatal. Ultimately, all acmetool cares about is that a challenge completes successfully after having attempted all possible preparations. It doesn't know or care "(em "why")" a challenge succeeds, only that it succeeded.")
          (p "(For HTTP-based challenges, acmetool self-tests its ability to complete the challenge by issuing a request for the same URL which will be requested by the ACME server, and does not proceed if this does not validate. Thus, HTTP-based challenges will never work if you are running some sort of weird split-horizon configuration where challenge files are retrievable only from the internet but not the local machine. In this case, you must disable acmetool's HTTP self-test functionality.)")
          )

     (sec "The state storage schema"
          (p "The format of acmetool's state directory is authoritatively documented here. TODO What follows is a summary of the more important parts.")
          (figure "Options supported by target files"
                  (listing "\
satisfy:
  names:
    - example.com       # The names you want on the certificate.
    - www.example.com

request:
  provider:               # ACME Directory URL. Normally set in conf/target only.
  ocsp-must-staple: true  # Request OCSP Must Staple. Use with care.
  challenge:
    webroot-paths:        # You can specify custom webroot paths.
      - /var/www
    http-ports:           # You can specify different ports for proxying.
      - 123               # Defaults to listening on localhost.
      - 456
      - 0.0.0.0:789       # Global listen.
    http-self-test: false # Defaults to true. If false, will not perform self-test
                          # but will assume challenge can be completed. Rarely needed.
    env:                  # Optionally set environment variables to be passed to hooks.
      FOO: BAR
  key:                    # What sort of key will be used for this certificate?
    type: rsa|ecdsa
    rsa-size: 2048
    ecdsa-curve: nistp256
    id: krzh2akn...       # If specified, the key ID to use to generate new certificates.
                          # If not specified, a new private key will always be generated.
                          # Useful for key pinning.

priority: 0"))
          (dict
            (dice (dick (tt "live")" directory")
                  (dicb (p "Contains symlinks from hostnames to certificate directories. Each certificate cirectory contains "(tt "cert")", "(tt "chain")", "(tt "fullchain")" and "(tt "privkey")" files. (If you are using HAProxy and have chosen to install the HAProxy hook script, a "(tt "haproxy")" file will also be available containing key, certificate and chain all in one.)")
                        (p "You should configure your web server in terms of paths like "(tt "/var/lib/acme/live/example.com/{cert,chain,fullchain,privkey}")".")))
            (dice (dick (tt "desired")" directory")
                  (dicb (p "Contains targetfiles. These determine the certificates which will be requested. Each target file is a YAML file, split into two principal sections: the "(tt "satisfy")" section and the "(tt "request")" section.")
                        (p "The "(tt "satisfy")" section dictates what conditions must be met in order for a certificate to meet a target (and thus be selected for symlinking under the "(tt "live")" directory). The "(tt "request")" section dictates the parameters for requesting new certificates, but nothing under it determines "(em "whether")" a certificate is requested.")
                        (p "Finally, the "(tt "priority")" value determines which target is used for a hostname when there are multiple targets for the same hostname. Higher priorities take precedence. The default priority is 0.")
                        (p "In most cases, you will set only "(tt "satisfy.names")" in a target file, and will set all other settings in the "(em "default target file")", which is located at "(tt "conf/target")". The quickstart wizard sets this file up for you. All settings in the default target file are inherited by targets, but can be overridden individually.")))
            (dice (dick "HAProxy support")
                  (dicb (p "If you have chosen to install the HAProxy hook script, each certificate directory will also have a coalesced "(tt "haproxy")" file containing certificate chain and private key. There will also be a "(tt "haproxy")" directory mapping from hostnames directly to these files.")))
            (dice (dick (tt "accounts")" directory")
                  (dicb (p "ACME account keys and state information. You don't need to worry about this.")))
            (dice (dick (tt "certs")" and "(tt "keys")" directories")
                  (dicb (p "Contains certificates and keys used to satisfy targets. However, you should never need to reference these directories directly."))))
          (p "Please note that it is a requirement that the state directory not straddle filesystem boundaries. That is, all files under "(tt "/var/lib/acme")" must lie on the same filesystem."))
     (sec "Response files"
          (p "It is possible to automatically provide responses to any question acmetool can ask.")
          (p "To do this, you provide the "(tt "--response-file")" flag, with the path to a YAML file containing response information. An example of such a file is here. TODO")
          (p "If you don't provide a "(tt "--response-file")" flag, acmetool will try to look for one at "(tt "/var/lib/acme/conf/responses")". If using a response file, it's recommended that you place it at this location.")
          (p "The file specifies key-value pairs. Each key is a prompt ID. (You can find these by grepping the source code for "(tt "UniqueID")".)")
          (p "For messages which simply require acknowledgement, specify "(tt "true")" to bypass them. Yes/no prompts should have a boolean value specified. The example response file is demonstrative.")
          (p "You should specify "(tt "--batch")" when using a response file to prevent acmetool from trying to prompt the user and fail instead, in case it tries to ask anything which you don't have a response for in your response file."))

     (sec "Hooks"
          (sec "Notification hooks"
               (p "The quickstart wizard installs default notification hooks to reload common webservers and other services after acmetool changes the preferred certificate for a hostname. These hooks are executable shell scripts and you can, if you wish, substitute your own. The default hooks are good bases from which to make your own customisations.")
               (p "You can use notification hooks to reload webservers, distribute certificates and private keys to other servers, or convert certificates and private keys into another format which is required by some daemon. For example, HAProxy support is implemented entirely via hooks.")
               (p "The event type is "(tt "live-updated")"."))
          (sec "Challenge hooks"
               (p "In some complex use cases, it may be necessary to install HTTP challenge files via some arbitrary programmatic means, rather than via one of the standard methods of webroot, proxy, redirector or listener.")
               (p "Challenge hooks are executed when challenge files need to be added or removed. Your hook must be synchronous; it must exit only when the challenge file is definitely in place and is globally accessible.")
               (p "See the specification for more information. TODO")
               (p "Challenge hooks are supported for HTTP, TLS-SNI and DNS challenges. A list of third party challenge hook scripts can be found here. TODO")))
     (sec "Command line options"
          (p "See the acmetool(8) manual page. TODO"))
     (sec "Troubleshooting"
          (p "Passing "(tt "--xlog.severity=debug")" increases the logging verbosity of acmetool and should be your first troubleshooting strategy."))
     (sec "FAQ"
          (sec "I've selected the (webroot/proxy/redirector/listener) challenge method, but I'm seeing log entries for other methods, or for webroots other than the one I configured."
               (p "This is normal. By design, acmetool always tries anything which might work, and these errors are nonfatal so long as "(em "something")" works. The challenge method you select in the quickstart wizard determines only whether to ask you for a webroot path, and whether to install the redirector (if you are using system). The webroot path "(tt "/var/run/acme/acme-challenge")", as a standard location, will always be tried in addition to any webroot your specify, as will proxy and listener mode ports.")
               (p "For more information, see challenge completion philosophy. TODO")))
     (sec "Annex: Root-configured non-root operation"
          (p "The following steps describe how you can, as root, take a series of steps that allows you to invoke acmetool as a non-root user, thereby limiting your attack surface and the degree to which you trust acmetool.")
          (p "It is also possible to use acmetool without you having access to root at all. In this case, place acmetool in a location of your choice and pass the "(tt "--state")" and "(tt "--hooks")" flags with appropriate paths of your choice to all invocations of acmetool.")
          (sec "Rootless setup as root"
               (p "acmetool has experimental support for root-free operation.")
               (p "In order to run root-free, after installing acmetool in "(tt "/usr/local/bin")" (or wherever you want it), before running acmetool, do the following:")
               (ul
                 (li (p "Create a new user "(tt "acme")" (or whatever you want)."))
                 (li (p "Create the directory "(tt "/var/lib/acme")" and change the owning user and group to "(tt "acme")". (You can use a different directory, but you must then make sure you pass "(tt "--state PATH")" to all invocations of acmetool.)"))
                 (li (p "Create the directory "(tt "/usr/lib/acme/hooks")" (or "(tt "/usr/libexec/acme/hooks")" on distros which use libexec). Make it writable by "(tt "acme")" for the time being by changing the group to "(tt "acme")" and making the directory group-writable. (You can make this read-only after running the quickstart process, which places some shell scripts in here to reload servers. You can audit these scripts yourself or use your own if you wish.)"))
                 (li (p "Change to the user "(tt "acme")" and run "(tt "acmetool quickstart")".")
                     (listing "$ sudo -u acme acmetool quickstart")
                     (p "A crontab will be installed automatically as the "(tt "acme")" user; you may wish to examine it."))
                 (li (p "As root, make the "(tt "hooks")" directory root-owned/not group writable once more. Ensure that the scripts are root-owned:")
                     (listing "# chown -R root:root /usr/lib*/acme/hooks\n# chmod 755 /usr/lib*/acme/hooks")
                     (p "Inspect the hook scripts if you wish. Mark the hook scripts setuid:")
                     (listing "chmod u+s /usr/lib*/acme/hooks/*")
                     (p "UNIX systems don't support setuid shell scripts, so this bit is ignored. Rather, acmetool takes it as a flag to tell it to run these scripts via "(tt "sudo")". This is necessary so that web servers, etc. can be reloaded.")
                     (p "The conditions for running using "(tt "sudo")" are that the files have the setuid bit set, that they be owned by root, that they be scripts and not binaries, and that acmetool is not being run as root."))
                 (li (p "Setup sudo. You will need to edit the sudoers file so that the hook scripts (which you have inspected and trust) can be executed by acmetool. It is essential that these have the "(tt "NOPASSWD")" flag as the scripts must be executable noninteractively.")
                     (listing "# visudo")
                     (p "Add the line:")
                     (listing "acme ALL=(root) NOPASSWD: /usr/lib/acme/hooks/"))
                 (li (p "Setup your challenge method:")
                     (dict
                       (dice (dick "Webroot")
                             (dicb (p "Make sure the "(tt "acme")" user can write to the webroot directory you configured.")))
                       (dice (dick "Redirector")
                             (dicb (p "Make sure the directory "(tt "/var/run/acme/acme-challenge")" is writable by the "(tt "acme")" user. acmetool puts challenges here because the redirector looks here (internally it's a glorified webroot mode).")
                                   (p "Note that "(tt "/var/run")" will be a tmpfs on many modern OSes, so the directory ceases to exist on reboots. The redirector will try to create the directory (as user root, mode 0755) if it doesn't exist. This happens before the redirector drops privileges from root. (It has to run as root initially to bind to port 80.)")
                                   (p "A configuration option has been added to make the redirector ensure that the directory is writable by a certain group when starting up. When this option is used, mode 0775 is used instead and the group owner is changed to a given GID.")
                                   (p "Pass "(tt "--challenge-gid=GID")" to "(tt "acmetool redirector")" (edit your service manager's configuration, e.g. the systemd unit file), where GID is the numeric group ID of the group owner for the challenge directory (i.e. the GID of the "(tt "acme")" group). (Group names rather than IDs may be supported on some platforms, but this is not guaranteed and will vary. Use of a GID is recommended.)")))
                       (dice (dick "Proxy")
                             (dicb (p "If you are using the proxy method, you won't be able to listen on port 402 as a non-root user. Use port 4402 instead, which acmetool will also try to use.")))
                       (dice (dick "Listener")
                             (dicb (p "This is not usable under non-root operation unless you can enable acmetool to bind to ports 80/443. On Linux you can do this by running "(tt "setcap cap_net_bind_service=+ep /path/to/acmetool")" as root. Other POSIX platforms may have sysctls to allow non-root processes to bind to low ports. However, this mode is not really useful for anything other than development anyway.")))

                       (dice (dick "Hook")
                             (dicb (p "See Challenge Hooks. TODO")))

                       )
                     )
                 )
               )
          )
     (sec "Annex: External resources and third party extensions"
          (p "The list of various tutorials, hook scripts and other integrations people have made for acmetool is now maintained in the wiki. TODO"))))

;; Man pages                                                               {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define (man-pages)
  (sec "Manual Pages"
    (sec "acmetool"
         (sec "Name"
              (p "acmetool — request certificates from ACME servers automatically"))
         (sec "Synopsis"
              (p (tt "acmetool [flags] <subcommand> [args...]")))
         (sec "Description"
              (p "acmetool is a utility for the automated retrieval, management and renewal of certificates from ACME servers such as Let's Encrypt. It emphasises automation, idempotency and the minimisation of state.")
              (p "You use acmetool by configuring targets (typically using the "(tt "want")" command). acmetool then requests certificates as necessary to satisfy the configured targets. New certificates are requested where existing ones are soon to expire.")
              (p "acmetool stores its state in a state directory. It can be specified on invocation via the "(tt "--state")" option; otherwise, the path in "(tt "ACME_STATE_DIR")" is used, or, failing that, the path "(tt "/var/lib/acme")" (recommended).")
              (p "The "(tt "--xlog")" options control the logging. The "(tt "--service")" options control privilege dropping and daemonization and are applicable only to the "(tt "redirector") " subcommand."))

         (sec "Global Options"
              (dict
                (dice (dick "--help")
                      (dicb (p "Show context-sensitive help TODO.")))
                (dice (dick "--version")
                      (dicb (p "Print version information.")))
                (dice (dick "--state=/var/lib/acme")
                      (dicb (p "Path to the ACME State Directory. (env: "(tt "ACME_STATE_DIR")")")))
                (dice (dick "--hooks=/usr/lib[exec]/acme/hooks/")
                      (dicb (p "Path to the ACME Hooks Directory. (env: "(tt "ACME_HOOKS_DIR")")")))
                (dice (dick "--response-file=$ACME_STATE_DIR/conf/responses")
                      (dicb (p "Read dialog responses from the given YAML file.")))
                (dice (dick "--batch")
                      (dicb (p "Do not attempt interaction; useful for cron jobs. (acmetool can still obtain responses from a response file, if one was provided.)")))
                (dice (dick "--stdio")
                      (dicb (p "Don't attempt to use console dialogs; fall back to stdio prompts.")))

                (dice (dick "Logging options")
                      (dicb (dict
                        (dice (dick "--xlog.severity=SEVERITY")
                              (dicb (p "Set logging severity (any syslog severity name or number).")))
                        (dice (dick "--xlog.stderr")
                              (dicb (p "Log to stderr? Defaults to enabled.")))
                        (dice (dick "--xlog.stderrseverity=SEVERITY")
                              (dicb (p "Set stderr logging severity.")))
                        (dice (dick "--xlog.file=FILE")
                              (dicb (p "Log to file.")))
                        (dice (dick "--xlog.fileseverity=SEVERITY")
                              (dicb (p "Set file logging severity.")))
                        (dice (dick "--xlog.syslog")
                              (dicb (p "Log to syslog?")))
                        (dice (dick "--xlog.facility=FACILITY")
                              (dicb (p "Syslog facility to log to")))
                        (dice (dick "--xlog.journal")
                              (dicb (p "Log to systemd journal?")))
                        (dice (dick "--xlog.journalseverity=SEVERITY")
                              (dicb (p "Set systemd journal logging severity."))))))))

         (sec "Subcommands"
              (sec "help"
                   (p "Show help."))
              (sec "reconcile"
                   (p (tt "reconcile [flags]"))
                   (p "Reconcile ACME state, idempotently requesting and renewing certificates to satisfy configured targets.")
                   (p "This is the default command."))
              (sec "cull"
                   (p (tt "cull [flags]"))
                   (p "Delete expired, unused certificates."))
              (sec "status"
                   (p (tt "status"))
                   (p "Show active configuration."))
              (sec "want"
                   (p (tt "want [flags] <hostname>..."))
                   (p "Add a target with one or more hostnames.")
                   (p "Options:")
                   (dict
                       (dice (dick "--no-reconcile")
                             (dicb (p "Ordinarily, "(tt "acmetool want")" always reconciles after adding a new target. Specify this flag to add a target without reconciling.")))))
              (sec "unwant"
                   (p (tt "unwant <hostname>..."))
                   (p "Modify targets to remove any mentions of the given hostname."))
              (sec "quickstart"
                   (p (tt "quickstart [flags]"))
                   (p "Interactively ask some getting started questions (recommended).")
                   (p "Options:")
                   (dict
                      (dice (dick "--expert")
                            (dicb (p "Ask more questions, such as what kind of keys to use for certificates.")))))
              (sec "redirector"
                   (p (tt "redirector [flags]"))
                   (p "HTTP to HTTPS redirector with challenge response support.")
                   (p "Options:")
                      (dict
                          (dice (dick "--service.uid=UID")
                                (dicb (p "UID to run as (default: don't drop privileges). Depending on how acmetool was built, a username might also be supported here.")))
                          (dice (dick "--service.gid=GID")
                                (dicb (p "GID to run as (default: don't drop privileges). Depending on how acmetool was built, a group name might also be supported here.")))
                          (dice (dick "--service.daemon")
                                (dicb (p "Run as daemon? (doesn't fork)")))
                          (dice (dick "--service.stderr")
                                (dicb (p "Keep stderr when daemonizing")))
                          (dice (dick "--service.chroot=/var/run/acme/acme-challenge")
                                (dicb (p "Chroot to a directory (must set UID, GID) (set to “"(tt "/")"” to disable)")))
                          (dice (dick "--service.pidfile=PIDFILE")
                                (dicb (p "Write PID to given filename and hold a write lock")))
                          (dice (dick "--service.fork")
                                (dicb (p "Fork? (implies "(tt "--service.daemon")")")))
                          (dice (dick "--service.debugserveraddr=HOST:PORT")
                                (dicb (p "If set, start a Go debug server listening on this address. Do not specify a public address. For development use only. Disabled by default.")))
                          (dice (dick "--service.cpuprofile=FILE")
                                (dicb (p "Write CPU profile to file.")))
                          (dice (dick "--path=/var/run/acme/acme-challenge")
                                (dicb (p "Path to serve challenge files from.")))
                          (dice (dick "--challenge-gid=GID")
                                (dicb (p "If set, the challenge file directory will be set to have this GID and will have a mode of 775 set rather than 755.")))
                          (dice (dick "--bind=:80")
                                (dicb (p "Bind address for HTTP redirector to listen on.")))
                          (dice (dick "--status-code=308")
                                (dicb (p "HTTP status code to use when redirecting.")))
                          (dice (dick "--read-timeout=10s")
                                (dicb (p "Maximum duration before timing out read of the request.")))
                          (dice (dick "--write-timeout=20s")
                                (dicb (p "Maximum duration before timing out write of the request.")))))
              (sec "test-notify"
                   (p (tt "test-notify <hostname>..."))
                   (p "Test-execute notification hooks as though given hostnames wer eupdated."))
              (sec "import-jwk-account"
                   (p (tt "import-jwk-account <provider-url> <private-key-file>"))
                   (p "Import a JWK-format account key."))
              (sec "import-pem-account"
                   (p (tt "import-pem-account <provider-url> <private-key-file>"))
                   (p "Import a PEM-format account key."))
              (sec "import-key"
                   (p (tt "import-key <private-key-file>"))
                   (p "Import a certificate private key."))
              (sec "import-le"
                   (p (tt "import-le <le-state-path>"))
                   (p "Import a Let's Encrypt (certbot) client state directory."))
              (sec "revoke"
                   (p (tt "revoke <certificate-id-or-path>"))
                   (p "Revoke a certificate."))
              (sec "account-thumbprint"
                   (p (tt "account-thumbprint"))
                   (p "Prints account thumbprints."))
              (sec "account-url"
                   (p (tt "account-url"))
                   (p "Prints account URL.")))
         (sec "Author"
              (p "© 2015—2021 Hugo Landau <hlandau@devever.net>")
              (p "acmetool is licenced under the MIT License."))
         (sec "See Also"
              (p "Additional documentation can be found at <https://hlandau.github.io/acmetool/>.")
              (p "Report bugs at <https://github.com/hlandau/acmetool/issues>."))
         )))

;; ACME State Storage Specification                                        {{{1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(define (acme-state-storage-specification)
  (sec "ACME State Storage Specification"
    (p "The ACME State Storage Specification (ACME-SSS) specifies how an ACME
       client can store state information in a directory on the local system in
       a way that facilitates its own access to and mutation of its state and
       the exposure of certificates and keys to other system services as
       required.")
    (p "This specification relates to the use of ACME but has no official endorsement.")
    (p "This specification is intended for use on POSIX-like systems.")

    (sec "Synopsis"
      (p "The following example shows a state directory configured to obtain a
         certificate with hostnames "(tt "example.com")" and "(tt "www.example.com")". No state
         other than that shown below is used.")

      (figure "Example of a configured state directory"
        (listing "\
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

      tmp/                  ; (used for writing files only)\
")))

    (sec "Preferred Location"
         (p "All ACME state is stored within a directory, the State Directory. On UNIX-like systems,
             this directory SHOULD be "(tt "/var/lib/acme")"."))

    (sec "Directory Tree"
         (sec "desired"
            (p "An ACME State Directory expresses targets in the form of
               desired hostnames for which certificates are required. This
               normatively expresses the target set of domains.")
            (p "The desired hostnames list is a directory named "(tt "desired")"
               inside the State Directory, containing zero or more files. Each
               file represents a target.")
            (p "The function of an implementation of this specification is simply
               this: to ensure that currently valid certificates are always provisioned
               which provide for all hostnames expressed across all targets.")
            (p "Each target is represented as a YAML file (referred to as a target file). The file schema looks like this:")
            (figure "Rough structure of a target file"
              (listing "\
satisfy:
  names:
    - example.com
    - www.example.com
    - foo.example.com

request:
  names:
    ...
  provider: (URL of ACME server)

priority: 0\
"))
            (p "The target file is principally divided into "(tt "satisfy")"
               and "(tt "request")" sections. The "(tt "satisfy")" section
               controls the conditions which must be satisfied by a certificate
               in order to satisfy this target. The "(tt "request")" section
               controls the parameters of a new certificate request made to
               satisfy the target.")
            (sec "Conditions to be satisfied"
              (p "The "(tt "satisfy")" section can contain the following values:")
              (dict
                (dice (dick (tt "names"))
                      (dicb (p "A list of hostname strings. If not set, and the filename is a valid hostname, defaults to a list containing only that hostname. Hostnames SHOULD be in lowercase with no trailing dot but hostnames not in this form MUST be accepted and so canonicalized. IDN domain names in Unicode form MUST be converted to their equivalent ASCII form. (All text files in a State Directory must be UTF-8 encoded.")))
                (dice (dick (tt "key"))
                      (dicb (p "Zero or more of the following:") (dict
                        (dice
                          (dick (tt "type"))
                          (dicb (p "Optional string specifying “”, “"(tt "rsa")"” or “"(tt "ecdsa")"”. If set to a non-empty value, only satisfied by keys with a public key of that type."))))))
                (dice (dick (tt "margin"))
                      (dicb (p "Optional positive integer. If set, expresses the number of days before expiry at which a certificate should be replaced. The default value is implementation-dependent."))))
              (p "(The lumping of hostnames into different target files controls when separate certificates are issued, and when single certificates with multiple SANs are issued. For example, creating two empty files, "(tt "example.com")" and "(tt "www.example.com")", would result in two certificates. Creating a single file "(tt "example.com")" which specifies names to be satisfied of "(tt "example.com")" and "(tt "www.example.com")" would result in one certificate with both names.)"))

            (sec "Certificate request parameters"
                 (p "The "(tt "request ")" section can contain the following values:")
                 (dict
                   (dice (dick (tt "names"))
                         (dicb (p "A list of hostname strings. Defaults to the names set under "(tt "satisfy")". This setting is specified for design parity, but it is not envisioned that a user will ever need to set it explicitly.")))
                   (dice (dick (tt "provider"))
                         (dicb (p "A string which is the URL of an ACME server from which to request certificates. Optional; if not specified, an implementation-specific default ACME server is used.")))))

            (sec "Backwards compatibility"
                 (p "For compatibility with previous versions, implementations SHOULD check for keys "(tt "names")" and "(tt "provider")" at the root level if present, move them to the "(tt "satisfy")" and "(tt "request")" sections respectively."))

            (sec "Target set label"
                 (p "The "(tt "label")" value is an optional string and defaults to “”."))

            (sec "Target set disjunction priority"
                 (p "The "(tt "priority")" value is special. It is an integer defaulting to 0."))
            (sec "Target set disjunction procedure"
                 (p "In order to ensure consistent and deterministic behaviour, and to minimise the number of certificate requests which need to be made in regard of overlapping name sets, the sets of names to be satisfied by each target are modified to ensure that the sets are fully disjoint. That is, any given hostname must appear in at most one target's list of names to be satisfied.")
                 (p "Note that this not affect what hostnames are "(em "requested")" when a target is used to request a new certificate.")
                 (p "The procedure operates as follows for all targets with a given label:")
                 (ul
                   (li (p "Take the list of targets and sort it in descending order of priority value.
                           For targets with equal priority, tiebreak using the number of hostnames to be satisfied in descending order. Where the number of hostnames is equal, the tiebreaker is implementation-specified, but SHOULD be deterministic."))
                   (li (p "Now iterate through the targets in that order. Create an empty dictionary mapping hostnames to targets. This dictionary shall be called the Hostname-Target Mapping and should be retained in memory even after the disjunction procedure is completed.")
                       (ul
                         (li (p "For each hostname to be satisfied for a target, if that hostname is not already in the dictionary, add it, pointing to the given target."))
                         (li (p "Copy the list of hostnames to be satisfied by the given target, and remove any hostnames from it which were already in the dictionary (i.e., where the map does not point to this target). This modified hostname list is called the reduced set of hostnames to be satisfied.")))))
                 (p "Keep both the full set of hostnames to be satisfied and the reduced set of hostnames to be satisfied in memory for each target. The on-disk target files are not modified.")
                 (p "Wildcard certificates may be requested just as the wildcard name would be encoded in a certificate. For example, an empty file named "(tt "*.example.com")" could be created in the "(tt "desired")" directory.")
                 (sec "Disjunction example"
                      (p "This section is non-normative. Suppose that the following targets were created.")
                      (figure "A set of targets"
                              (listing "\
Target 01: a.example.com  b.example.com  c.example.com
Target 02: a.example.com  b.example.com
Target 03:                b.example.com  c.example.com
Target 04: a.example.com                 c.example.com
Target 05: a.example.com
Target 06:                b.example.com
Target 07:                               c.example.com
Target 08: c.example.com  d.example.com  e.example.com  f.example.com
Target 09: c.example.com  d.example.com
Target 10: c.example.com  d.example.com  e.example.com"))
                      (p "Suppose that all targets have the default priority zero and have filenames "(tt "Target 01")", etc. The targets would be sorted as follows. The hostnames in brackets are not in the reduced set.")
                      (figure "A reduced set of targets"
                              (listing "\
Target 08: c.example.com  d.example.com  e.example.com  f.example.com
Target 01: a.example.com  b.example.com [c.example.com]
Target 10:[c.example.com][d.example.com][e.example.com]
Target 02:[a.example.com][b.example.com]
Target 03:               [b.example.com][c.example.com]
Target 04:[a.example.com]               [c.example.com]
Target 09:[c.example.com][d.example.com]
Target 05:[a.example.com]
Target 06:               [b.example.com]
Target 07:                              [c.example.com]"))
                      (p "Suppose that Target 01 was changed to have a priority of 10. The sorted, reduced targets would now look like this:")
                      (figure "A reduced set of targets (2)"
                              (listing "\
Target 01: a.example.com  b.example.com  c.example.com
Target 08:[c.example.com] d.example.com  e.example.com  f.example.com
Target 10:[c.example.com][d.example.com][e.example.com]
Target 02:[a.example.com][b.example.com]
Target 03:               [b.example.com][c.example.com]
Target 04:[a.example.com]               [c.example.com]
Target 09:[c.example.com][d.example.com]
Target 05:[a.example.com]
Target 06:               [b.example.com]
Target 07:                              [c.example.com]"))))
                  (sec "Extensions for specific implementations: acmetool"
                       (p "This section is non-normative, added as a practicality since this document serves as both specification and documentation. acmetool supports the following extensions:")
                       (figure "Extensions to target files supported by acmetool"
                               (listing "\
request:
  # Determines whether RSA or ECDSA keys are used. ECDSA keys must be
  # supported by the server. Let's Encrypt does not yet support ECDSA
  # keys, though support is imminent. Default RSA.
  key:
    type: rsa (must be \"rsa\" or \"ecdsa\")

    # RSA modulus size when using an RSA key. Default 2048 bits.
    #
    # Legacy compatibility: if not present, the number of bits may be
    # contained in a file \"rsa-key-size\" inside the conf directory.
    rsa-size: 2048

    # ECDSA curve when using an ecdsa key. Default \"nistp256\".
    #
    # It is strongly recommended that you use nistp256. Let's Encrypt
    # will not support nistp521.
    ecdsa-curve: nistp256 (must be \"nistp256\", \"nistp384\" or \"nistp521\")

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
    # Legacy compatibility: the file \"webroot-path\" in the conf directory
    # contains a list of webroot paths, one per line.
    webroot-paths:
      - /some/webroot/path/.well-known/acme-challenge

    # A list of additional ports to listen on. Each item can be a port
    # number, or an explicit bind address (e.g. \"[::1]:402\"). Specifying a
    # port number x is equivalent to specifying \"[::1]:x\" and \"127.0.0.1:x\".
    http-ports:
      - 80
      - 402
      - 4402

    # Defaults to true. If false, will not perform self-test but will assume
    # challenge can be completed. Rarely needed.
    http-self-test: true

    # Optionally set environment variables to be passed to hooks.
    env:
      FOO: BAR"))
                    ))
            (sec "accounts"
                 (p "An ACME State Directory MUST contain a subdirectory "(tt "accounts")" which contains account-specific information. It contains zero or more subdirectories, each of which relates to a specific account. Each subdirectory MUST be named after the Account ID.")
                 (p "Each account subdirectory MUST contain a file "(tt "privkey")" which MUST contain the account private key in PEM form.")
                 (p "An ACME client which needs to request a certificate from a given provider (as expressed by a target or used as a default) which finds that no account corresponding to that provider URL exists should generate a new account key and store it for the provider URL.")
                 )

            (sec "keys"
                 (p "An ACME State Directory MUST contain a subdirectory "(tt "keys")" which contains private keys used for certificates. It contains zero or more subdirectories, each of which relates to a specific key. Each subdirectory MUST be named after the Key ID.")
                 (p "Each key subdirectory MUST contain a file "(tt "privkey")" which MUST contain the private key in PEM form.")
                 (p "An ACME client creates keys as necessary to correspond to certificates it requests. An ACME client SHOULD create a new key for every certificate request unless expressly directed otherwise."))
            (sec "certs"
                 (p "An ACME State Directory MUST contain a subdirectory "(tt "certs")" which contains information about issued or requested certificates. It contains zero or more subdirectories, each of which relates to a specific certificate. Each subdirectory MUST be named after the Certificate ID.")
                 (p "Each certificate subdirectory MUST contain a file "(tt "url")" which contains the URL for the finalised order encoded in UTF-8. Clients MUST NOT include trailing newlines or whitespace but SHOULD accept such whitespace and strip it.")
                 (p "NOTE: In previous versious of this specification (which targeted the draft ACME protocol prior to the addition of orders), the URL contained in the "(tt "url")" file was the URL to the certificate. Such certificates may still exist in a state directory; it is recommended that implementations be able to detect whether an URL leads to a certificate or order via the Content-Type of the response yielded when dereferencing the URL. These old certificate directories (and some older new certificate directories) will also lack an "(tt "account")" symlink.")
                 (p "A client SHOULD automatically delete any certificate directory if the certificate it contains is expired AND is not referenced by the "(tt "live")" directory. Certificates which have expired but which are still referenced by the "(tt "live")" directory MUST NOT be deleted to avoid breaking reliant applications.")
                 (p "A certificate subdirectory MAY also contain information obtained from the URL contained in the "(tt "url")" file. If an ACME client finds only an "(tt "url")" file, it MUST retrieve the certificate information to ensure that local system services can make use of the certificate:")
                 (ul
                   (li (p "If retrieval of the certificate fails with a permanent error (e.g. 404), the certificate directory SHOULD be deleted."))
                   (li (p "If retrieval of the certificate fails with a temporary error (e.g. 202), the client tries again later. If provided, the Retry-After HTTP header should be consulted."))
                   (li (p "If retrieval of the certificate yields an "(tt "application/json")" resource suggesting an order (rather than the certificate itself), it is parsed as an order to find the certificate URL. If the order is still in status "(tt "processing")", handle it like a temporary error as above; if the order has somehow transitioned to "(tt "invalid")", handle it like a permanent error as above."))
                   (li (p "If retrieval of the certificate succeeds, but the private key required to use it cannot be found, the certificate directory SHOULD be deleted.")))
                 (p "After having successfully retrieved the certificate, the following files MUST be written in the certificate subdirectory:")
                 (dict
                   (dice (dick (tt "cert"))
                         (dicb (p "A file which MUST contain the PEM-encoded certificate.")))
                   (dice (dick (tt "chain"))
                         (dicb (p "A file which MUST contain the PEM-encoded certificate chain, i.e., the concatenation of the PEM encodings of all certificates but for the issued certificate itself and the root certificate which are necessary to validate the certificate. In other words, this contains any necessary intermediate certificates.")))
                   (dice (dick (tt "fullchain"))
                         (dicb (p "A file which MUST contain the concatenation of the "(tt "cert")" and "(tt "chain")" files.")))
                   (dice (dick (tt "privkey"))
                         (dicb (p "This MUST be a relative symlink to the "(tt "privkey")" file of the private key used to create the certificate (i.e. a symlink pointing to "(tt "../../keys/(key ID)/privkey")").")))))
            (sec "live"
                 (p "An ACME State Directory MUST contain a subdirectory "(tt "live")". It contains zero or more relative symlinks, each of which MUST link to a subdirectory of the "(tt "certs")" directory. The name of each symlink MUST be a hostname which is expressed, or was previously expressed by one or more targets, followed by a colon and the label of the target. If the label of the target is "", the colon is omitted.")
                 (p "The "(tt "live")" directory MUST point to the Most Preferred Certificate for each target, as specified below. Thus an application requiring a certificate for a given hostname can unconditionally specify "(tt "/var/lib/acme/live/example.com/{cert,privkey}")" for the certificate, private key, etc."))
            (sec "tmp, Rules for State Directory Mutation"
                 (p "An ACME State Directory MUST contain a subdirectory "(tt "tmp")" which is used for storing temporary files. This directory is used instead of some system-scope temporary directory to ensure that new files are created on the same filesystem and thus can be atomically renamed to their desired final locations in the ACME State Directory. For temporary files which do not require this, other temporary directories may be more suitable.")
                 (p "IMPORTANT: Any change to any object in the ACME State Directory MUST be one of the following operations:")
                 (ul
                   (li (p "An idempotent recursive directory creation ("(tt "mkdir -p")")."))
                   (li (p "Writing to a temporary file securely created with a high-entropy filename in "(tt "tmp")" and appropriately locked, then either atomically moving it to its desired location in the ACME State Directory (potentially overwriting an existing file) or deleting it (e.g. in the event of an error before the file is completely written)."))
                   (li (p "Securely creating a new symlink with a high-entropy filename in "(tt "tmp")", then either atomically moving it to its desired location in the ACME State Directory (potentially overwriting an existing symlink) or deleting it."))
                   (li (p "Atomically deleting a file or recursively deleting a directory."))
                   (li (p "Idempotently changing file or directory permissions or ownership to conform with security requirements."))
                   )
                 (p "When an ACME client finds files in the "(tt "tmp")" directory which it did not itself open (in its current invocation), it SHOULD delete them. It SHOULD perform this check whenever invoked.")
                 (p "Files MUST be created with the permissions they are to ultimately hold, not have their permissions modified afterwards. Where particular permissions are required of certain files, those permissions SHOULD be verified on every invocation of the client. Where particular permissions are required of a directory, those permissions MUST be verified before moving any file into that directory. Note that because all files begin in the "(tt "tmp")" directory, their permissions MUST be strictly as strict or stricter than the permissions of any direct or indirect parent directory, at least until the move is completed."))
            (sec "Permissions (POSIX)"
                 (p "The following permissions on a State Directory MUST be enforced:")
                 (ul
                   (li (p "The "(tt "accounts")", "(tt "keys")" and "(tt "tmp")" directories and all subdirectories within them MUST have mode 0770 or stricter. All files directly or ultimately within these directories MUST have mode 0660 or stricter, except for files in "(tt "tmp")", which MUST have the permissions appropriate for their ultimate location before they are moved to that location."))
                   (li (p "For all other files and directories, appropriate permissions MUST be enforced as determined by the implementation. Generally this will mean directories having mode 0755 and files having mode 0644. Files and directories MUST NOT be world-writable.")))
                 (p "The ownership of a State Directory and all files and directories directly or ultimately within it SHOULD be verified and enforced.")
                 )
            (sec "Use of Symlinks"
                 (p "All symlinks used within the State Directory MUST be unbroken, MUST point to locations within the State Directory and MUST be relatively expressed (i.e., they MUST NOT break if the State Directory were to be moved). Implementations SHOULD verify these properties for any symlinks they encounter in the State Directory."))) 

          (sec "Hooks"
               (p "It is desirable to provide extensibility in certain circumstances via the means of hooks. These hooks are implemented using executable shell scripts or binaries external to an implementation. Several types of hook are defined.")
               (p "All hooks are kept in a separate directory, the ACME Hooks Directory. The RECOMMENDED path is "(tt "/usr/lib/acme/hooks")", except for systems which use "(tt "/usr/libexec")", which SHOULD use "(tt "/usr/libexec/acme/hooks")".")
               (p "The hooks directory MUST contain only executable objects (i.e. executable scripts or binaries or symlinks to them). However, implementations SHOULD ignore non-executable objects. “Executable” here means executable in practical terms, and does not refer merely to the file having the executable bits set in its mode, which is a necessary but not sufficient condition.")
               (sec "Calling Convention"
                    (p "An ACME client MUST invoke hooks as follows: Take the list of objects in the hooks directory and sort them in ascending lexicographical order by filename. Execute each object in that order. If execution of an object fails, execution of subsequent objects MUST continue.")
                    (p "The first argument when invoking a hook is always the event type causing invocation of the hook.")
                    (p "When invoking a hook, the environment variable "(tt "ACME_STATE_DIR")" MUST be set to the absolute path of the State Directory.")
                    (p "A hook is invoked successfully if it exits with exit code 0. A hook which exits with exit code 42 indicates a lack of support for the event type. Any other exit code indicates an error."))

               (sec "sudo Protocol"
                    (p "It may be desirable for an implementation to run as an unprivileged user. In this case, it is necessary to have some way to elevate notification hooks so they can perform privileged operations such as restarting system services. Since most POSIX systems do not support the setuid bit on scripts, the use of “sudo” is suggested.")
                    (p "When an implementation is not running as root, and executes a hook, and that hook is owned by root, and it has the setuid bit set, and the OS does not (as currently configured) support setuid on scripts, and the “sudo” command is available, and the file begins with the characters "(tt "#!")", execute "(tt "sudo -n -- FILE EVENT-TYPE ARGS...")", where "(tt "FILE")" is the absolute path to the file and "(tt "ARGS")" are dictated by hook event type. Success is not guaranteed as the system administrator must have configured the sudoers file to allow this operation."))

               (sec "live-updated"
                    (p "The "(tt "live-updated")" hook is invoked when one or more symlinks in the "(tt "live")" directory are created or updated. There are no arguments.")
                    (p "Each object invoked MUST have passed to stdin a list of the names of the symlinks in the "(tt "live")" directory which have changed target, i.e. the hostnames for which the preferred certificate has changed. The hostnames are separated by newlines, and the final hostname also ends with a newline."))

               (sec "challenge-http-start, challenge-http-stop"
                    (p "These hooks are invoked when an HTTP challenge attempt begins and ends. They can be used to install challenge files at arbitrary locations.")
                    (p "The first argument is the hostname to which the challenge relates.")
                    (p "The second argument is the filename of the target file causing the challenge to be completed. This may be the empty string in some circumstances; for example, when an authorization is being obtained for the purposes of performing revocation rather than for obtaining a certificate.")
                    (p "The first argument is the filename which must be provisioned under "(tt "/.well-known/acme-challenge/")".")
                    (p "The required contents of the file is passed as stdin.")
                    (p "A hook should exit with exit code 0 only if it successfully installs or removes the challenge file. For "(tt "challenge-http-start")", an implementation may consider such an exit to authoritatively indicate that it is now feasible to complete the challenge.")
                    (p "Example call:")
                    (figure "Example invocation of a challenge-http-start hook"
                            (listing "\
echo evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nP1qzpXGymHBrUEepNY9HCsQk7K8KhOypzEt62jcerQ | \\
ACME_STATE_DIR=/var/lib/acme /usr/lib/acme/hooks/foo \\
  challenge-http-start example.com some-target-file \\
  evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA")))

                (sec "challenge-tls-sni-start, challenge-tls-sni-stop"
                     (p "These hooks are invoked when a TLS-SNI challenge begins and ends. They can be used to install the necessary validation certificate by arbitrary means.")
                     (p "The hook MUST return 0 only if it succeeds at provisioning/deprovisioning the challenge. When returning 0 in the "(tt "challenge-tls-sni-start")", it MUST return only once the certificate is globally visible.")
                     (p "The first argument is the hostname to which the challenge relates.")
                     (p "The second argument is the filename of the target file causing the challenge to be completed. This may be the empty string in some circumstances; for example, when an an authorization is being obtained for the purposes of performing revocation rather than for obtaining a certificate.")
                     (p "The third argument is the hostname which will be specified via SNI when the validation server checks for the certificate.")
                     (p "The fourth argument is an additional hostname which must appear in the certificate. Both hostnames must appear as dNSName SubjectAlternateNames in the certificate returned.")
                     (p "The third and fourth argument may be equal in some cases.")
                     (p "A PEM-encoded certificate followed by a PEM-encoded private key is fed on stdin. A hook can choose to provision this certificate to satisfy the challenge. It can also construct its own certificate."))

                (sec "challenge-dns-start, challenge-dns-stop"
                     (p "These hooks are invoked when a DNS challenge begins and ends. They can be used to install the necessary validation DNS records, for example via DNS UPDATE.")
                     (p "The hook MUST return 0 only if it succeeds at provisioning/deprovisioning the challenge. When returning 0 in the "(tt "challenge-dns-start")" case, it MUST return only once the record to be provisioned is globally visible at all of the authoritative nameservers for the applicable zone. The hook is not required to consider the effects of caching resolvers as ACME servers will perform the lookup directly.")
                     (p "The first argument is the hostname to which the challenge relates.")
                     (p "The second argument is the filename of the target file causing the challenge to be completed. This may be the empty string in some circumstances; for example, when an authorization is being obtained for the purposes of performing revocation rather than for obtaining a certificate.")
                     (p "The third argument is the value of the DNS TXT record to be provisioned.")
                     (p "Note that as per the ACME specification, the TXT record must be provisioned at "(tt "_acme-challenge.HOSTNAME")", where "(tt "HOSTNAME")" is the hostname given.")
                     (p "Example call:")
                     (figure "Example invocation of a challenge-dns-start hook"
                             (listing "\
ACME_STATE_DIR=/var/lib/acme /usr/lib/acme/hooks/foo \\
  challenge-dns-start example.com some-target-file \\
  evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"))))
          (sec "SRV-ID"
               (p "The desire for a certificate containing a SRV-ID subjectAltName is expressed by placing a file in the "(tt "desired")" directory named after the SRV-ID, e.g. "(tt "_xmpp-client.example.com")". This is recognised as a SRV-ID automatically by virtue of it starting with an underscore. Since hostnames may not contain underscores, this is not ambiguous.")
               (p "Support for SRV-ID in ACME implementations remains to be seen."))
          (sec "Operations"
            (sec "Conform"
                 (p "To conform a State Directory means to examine everything in the directory for consistency and validity. Permissions are changed as necessary to ensure they match the implementation's policy. The implementation verifies that all symlinks are unbroken, relative and point to locations within the State Directory. Remnant temporary files are deleted. Errors are indicated for any malformed directory (e.g. account directory with no private key, etc.)")
                 (p "This operation is idempotent."))
            (sec "Reconcile"
                 (p "A certificate can be described as "(tt "satisfying")" a target, or as being the Most Preferred Certificate for a target. These are distinct classifications, and neither implies the other. A certificate might be the Most Preferred Certificate for a target even though it does not satisfy it, because it is the “least worst option”. A certificate might satisfy a target but not be the Most Preferred Certificate for it.")
                 (p "The reconcile operation is the actual act of “building” the State Directory.")
                 (ul
                   (li (p "Begin by performing the conform operation."))
                   (li (p "If there are any uncached certificates (certificate directoriex containing only an "(tt "url")" file), cache them, waiting for them to become available (orders to finish processing, etc.) if necessary."))
                   (li (p "If there are any certificates marked for revocation (meaning that a "(tt "revoke")" file exists in the certificate directory), but which are not marked as being revoked (meaning that a "(tt "revoked")" file exists in the certificate directory), request revocation of the certificate and, having obtained confirmation of that revocation, create an empty file "(tt "revoked")" in the certificate directory."))
                   (li (p "For each target, satisfy the target.")
                       (p "To satisfy a target:")
                       (ul
                         (li (p "If there exists a certificate satisfying the target, the target is satisfied. Done."))
                         (li (p "Otherwise, request a certificate with the hostnames listed under the "(tt "request")" section of the target. If a certificate cannot be obtained, fail. Satisfy the target again.")
                             (p "When making certificate requests, use the provider/account information specified in the "(tt "request")" section.")))
                       (p "To request a certificate:")
                       (ul
                         (li (p "Create an order with the necessary identifiers and satisfy the authorizations specified within the newly created order. If the order becomes invalid due to a failed authorization, create another order and start again, until an order's authorization requirements are successfully fulfilled or it is determined that no further forward progress can be made regarding one or more authorizations."))
                         (li (p "Having obtained an order with status "(tt "ready")", form an appropriate CSR containing the SANs specified in the "(tt "request")" section of the applicable target and finalise the order. Write the order URL to the State Directory; there is no need to wait for it to exit the "(tt "processing")" state."))))
                   (li (p "Update the "(tt "live")" directory as follows:")
                       (ul
                         (li (p "For each (hostname, target) pair in the Hostname-Target Mapping, create a symlink for the hostname pointing to the Most Preferred Certificate for the target, if one exists."))))
                   (li (p "If any certificates were requested while satisfying targets, perform the Reconcile operation again; stop."))
                   (li (p "Optionally perform cleanup operations:")
                       (ul
                         (li (p "Delete the certificate directories for any cullable certificates."))
                         (li (p "Delete (optionally, securely erase) the key directories for any cullable private keys.")))))
                 (p "This operation is idempotent.")

                 (sec "Satisfying targets"
                      (p "A certificate satisfies a target if:")
                      (ul
                        (li (p "the private key for the certificate is available in the State Directory, and"))
                        (li (p "the certificate is not known to be revoked, and"))
                        (li (p "all stipulations listed in the "(tt "satisfy")" section of the target are met:")
                            (ul
                              (li (p "the "(tt "names")" stipulation is met if the dNSName SANs in a given certificate are a superset of the names specified.")))
                            (p "and"))
                        (li (p "the certificate is not self-signed, and"))
                        (li (p "the current time lies between the Not Before and Not After times, and"))
                        (li (p "the certificate is not near expiry."))))

                 (sec "Near expiry"
                      (p "A certificate is near expiry if the difference between the current time and the “Not After” time is less than some implementation-specific threshold. The RECOMMENDED threshold is 30 days or 33% of the validity period, whichever is lower."))
                 (sec "Most Preferred Certificate"
                      (p "The Most Preferred Certificate for a given target is determined as follows:")
                      (ul
                        (li (p "Certificates which satisfy the target are preferred over certificates that do not satisfy the target."))
                        (li (p "For two certificates neither of which satisfies the target, one is preferred over the other if the first criterion in the list of criteria for satisfying a target which it does not satisfy is later in the list of criteria than for the other.")
                            (p "For example, a revoked certificate for which a private key is available is preferred over a certificate for which no private key is available. A self-signed certificate with the right names is preferred over a self or CA-signed certificate with the wrong names. A self-signed certificate is preferred over a revoked certificate. (A revoked certificate may not be exemptible by a user; thus even a self-signed certificate is preferable to a certificate known to be revoked.)"))
                        (li (p "Certificates with later “Not After” times are preferred."))))
                 (sec "Cullability"
                      (p "A certificate is cullable if:")
                      (ul
                        (li (p "it is expired, and"))
                        (li (p "after reconciliation, it is unreferenced by any "(tt "live")" symlink.")))
                      (p "A private key is cullable if:")
                      (ul
                        (li (p "it does not relate to any known certificate, and"))
                        (li (p "it was not recently created or imported. The definition of “recently” is implementation-specific."))))
                 (sec "Revocation"
                      (p "A certificate is revoked by creating an empty file "(tt "revoke")" in the certificate directory and reconciling."))))
          (sec "Identifiers"
               (p "Accounts, keys and certificates are stored in directories named by their identifiers. Their identifiers are calculated as follows:")
               (dict
                 (dice (dick "Key ID")
                       (dicb (p "Lowercase base32 encoding with padding stripped of the SHA256 hash of the subjectPublicKeyInfo constructed from the private key.")))
                 (dice (dick "Account ID")
                       (dicb (p "Take the Directory URL for the ACME server. Take the hostname, port (if non-default) and path, stripping the scheme (e.g. "(tt "example.com/directory")"). If the path is "(tt "/")", strip it ("(tt "example.com/")" becomes "(tt "example.com")"). URL-encode this string so that any slashes are percent-encoded using lowercase hexadecimal. Take this strnig and append "(tt "/")" followed by the string formed by calculating a key ID using the account's private key.")
                             (p "For example, "(tt "example.com%2fdirectory/irq7564p5siu3zngnc2caqygp3v53dfmh6idwtpyfkxojssqglta")".")
                             (p "Each account directory is thus an account key-specific subdirectory of the string formed from the directory URL.")
                             (p "For production use the scheme MUST be "(tt "https")". In some cases, it may be desirable to test using HTTP. Where an HTTP URL is specified, it is prefixed with "(tt "http:")".")
                             (p "For example: "(tt "http:example.com%2fdirectory/irq7564p5siu3zngnc2caqygp3v53dfmh6idwtpyfkxojssqglta")".")))
                 (dice (dick "Certificate ID")
                       (dicb (p "A certificate ID must be assignable before a certificate has been issued, when only the public key and order URL are known.")
                             (p "Thus, the Certificate ID shall be the lowercase base32 encoding with padding stripped of the SHA256 hash of the order URL (or, for legacy certificates, the certificate URL).")
                             (p "A certificate directory is invalid if the "(tt "url")" file does not match the Certificate ID. Such a directory should be deleted.")))))
          (sec "Temporary Use of Self-Signed Certificates"
               (p "Some daemons may fail terminally when a certificate file referenced by their configuration is not present. Thus, where a client is unable to procure a certificate immediately, it MAY choose to provision a self-signed certificate referenced by symlinks under "(tt "live")" instead. This will allow a daemon to continue operating (perhaps serving non-TLS requests or requests for other hostnames) with reduced functionality.")
               (p "If a client uses such interim self-signed certificates, it MUST create an empty file "(tt "selfsigned")" in the certificate directory to indicate that the certificate is a self-signed certificate. The "(tt "url")" file MUST NOT exist. The "(tt "cert")" and "(tt "fullchain")" files MUST be identical, and the "(tt "chain")" file MUST exist and MUST be an empty file.")
               (p "The self-signed certificate MAY contain information in it which points out the configuration issue the certificate poses, for example by placing a short description of the problem in the O and OU fields, e.g.:")
               (listing "OU=ACME Cannot Acquire Certificate\nO=ACME Failure Please Check Server Logs")
               (p "The Certificate ID of a self-signed certificate is the string "(tt "selfsigned-")" followed by the lowercase base32 encoding with padding stripped of the SHA256 hash of the DER encoded certificate."))))


