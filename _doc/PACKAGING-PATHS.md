# On packaging acmetool for distribution: changing default paths

acmetool uses paths such as "/var/lib/acme" and "/usr/lib(exec)/acme/hooks" by
default. It may be desired to change these paths for the purposes of a specific
distribution. It is thus possible to override these paths when building acmetool.

The following arguments to `go build` demonstrate which paths may be customized
and how:

```sh
$ go build -ldflags '
    -X github.com/hlandau/acme/storage.RecommendedPath="/var/lib/acme"
    -X github.com/hlandau/acme/notify.DefaultHookPath="/usr/lib/acme/hooks"
  ' github.com/hlandau/acme/cmd/acmetool
```
