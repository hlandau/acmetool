# On packaging acmetool for distribution: changing default paths

acmetool uses paths such as "/var/lib/acme" and "/usr/lib(exec)/acme/hooks" by
default. It may be desired to change these paths for the purposes of a specific
distribution. It is thus possible to override these paths when building acmetool.

The following arguments to `go build` demonstrate which paths may be customized
and how. This example also includes version information, which ensures that
`--version` output will be informative.

If you set the BUILDNAME environment variable, you can specify a short,
one-line string providing your build information. This defaults, if not set, to
the date and hostname. (You could set it to a constant value if you are
pursing reproducible builds.)

```sh
$ go build -ldflags "
    -X git.devever.net/hlandau/acmetool/storage.RecommendedPath=\"/var/lib/acme\"
    -X git.devever.net/hlandau/acmetool/hooks.DefaultPath=\"/usr/lib/acme/hooks\"
    -X git.devever.net/hlandau/acmetool/responder.StandardWebrootPath=\"/var/run/acme/acme-challenge\"
    $($GOPATH/src/github.com/hlandau/buildinfo/gen git.devever.net/hlandau/acmetool)
  " git.devever.net/hlandau/acmetool
```
