<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# Policy Overrides

Operator overrides are merged after `policies/defaults/*.json`.

Supported layouts:

```text
policies/overrides/<server>.json
policies/overrides/<server>/<tool>.json
```

Tool-level overrides may use the paper-facing `capabilities` wrapper:

```json
{
  "tool": "read_file",
  "capabilities": {
    "filesystem": {
      "read": ["./workspace/**"]
    }
  }
}
```

Dictionary values merge recursively. List values are appended without
duplicates, so overrides only need to name the additional capabilities that an
audit event justifies.
