# Vendoring

We currently only vendor code which we want to build and ship ourselves.

## minijail

The current minijail version can be found in `minijail/ref`.

To update the vendored minijail code to a specific git reference `$REF`:

```bash
./update.sh https://chromium.googlesource.com/aosp/platform/external/minijail "${REF}"
```
