# acmetool Web Server Configuration Guide

## Redirector Mode

No configuration required, but ensure that your web server is not listening on port 80 and that the redirector service (`acmetool redirector`) is started.

## Proxy Mode

You can configure nginx/tengine for use with acmetool in proxy mode like follows:

### nginx/Tengine

```nginx
http {
  server {
    ... your configuration ...

    location /.well-known/acme-challenge/ {
      proxy_pass http://acmetool;
    }
  }

  upstream acmetool {
    server 127.0.0.1:402;
  }
}
```

Note that the configuration will need to be repeated for each vhost. You may
wish to avoid duplication by placing the applicable configuration in a separate
file and including it in each vhost.

### Apache httpd

```apache
  ProxyPass "/.well-known/acme-challenge" "http://127.0.0.1:402/.well-known/acme-challenge"
```

Ensure you load the modules `mod_proxy` and `mod_proxy_http`.

## Webroot Mode

Using nginx/tengine with acmetool in webroot mode shouldn't ordinarily need any
special webserver configuration if you specify
`WEBROOT/.well-known/acme-challenge` as the path, where `WEBROOT` is your webroot
(e.g. `/var/www`, `/srv/http`). But if you want to store challenges in a different
directory, you'll need to configure an alias.

If you want to store challenges in a different directory, the directory
`/var/run/acme/acme-challenge` is recommended.

You can configure nginx/tengine to serve such a directory as follows:

### nginx/Tengine

```nginx
http {
  server {
    location /.well-known/acme-challenge/ {
      alias /var/run/acme/acme-challenge/;
    }
  }
}
```

Note that the configuration will need to be repeated for each vhost. You may
wish to avoid duplication by placing the applicable configuration in a separate
file and including it in each vhost.

### Apache httpd

```apache
  Alias "/.well-known/acme-challenge/" "/var/run/acme/acme-challenge/"
  <Directory "/var/run/acme/acme-challenge">
    AllowOverride None
    Options None

    # If using Apache 2.4+:
    Require all granted

    # If using Apache 2.2 and lower:
    Order allow,deny
    Allow from all
  </Directory>
```
