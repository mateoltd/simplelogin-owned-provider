# Reviewed tracked frontend notices

This notice records the source mapping for frontend files tracked outside the
normal npm installation closure. Exact hashes, package license files, and source
archives are generated into the public-release bundle.

| Tracked material | Reviewed source | License | Relationship |
| --- | --- | --- | --- |
| `static/assets` Tabler distribution | `tabler-ui@0.0.34` | MIT | 477 files are byte-identical. `js/core.js` is fork-modified and is present in the owned-provider source archive. |
| Tabler-embedded jVectorMap | `jvectormap@2.0.3` | AGPL-3.0-only | Readable corresponding source is bundled. The local minified bytes are not byte-identical to the npm minified file, so the mapping is qualified rather than asserted as exact. |
| `static/vendor/clipboard.min.js` | `clipboard@2.0.4` | MIT | Byte-identical to `package/dist/clipboard.min.js`. |
| `static/vendor/bootstrap-social.min.css` | `bootstrap-social@5.1.1` | MIT | Readable LESS, SCSS, and CSS are bundled. The historical minifier is unknown. |
| `static/assets/js/vendors/base64.js` and `webauthn.js` | Duo Labs `py_webauthn` browser helpers | BSD-3-Clause | Preferred-form JavaScript and the upstream notice are tracked in the owned-provider source archive. |

Paddle.js is not tracked or redistributed from this repository. The application
loads it directly from Paddle's documented CDN. The former local fallback was
removed because no authoritative redistribution license was established for
those copied bytes.
