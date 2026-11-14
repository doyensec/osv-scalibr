# Docker Compose image extraction

By default, the extractor does not resolve Compose `include` or `extends`
references. It extracts images from the supplied manifest, including YAML anchors,
and can interpolate variables from a sibling `.env` read through the scan
filesystem. Service `env_file` and `label_file` resolution is disabled.

For trusted manifests on an on-disk scan root, enable external references in the
plugin configuration:

```textproto
plugin_specific {
  docker_compose_image {
    resolve_external_refs: true
  }
}
```

**Warning:** this lets compose-go read files accessible to the scanner process,
including files outside the scan root through absolute paths, relative paths, or
symlinks. Included projects can also load their own interpolation environment
files. This option is not a sandbox and must not be enabled for untrusted input.
Relative references are resolved from the manifest's on-disk directory. Purely
virtual scan filesystems are not supported with this option enabled.

Service `env_file` and `label_file` resolution remains disabled because those
values are not needed to extract image names. No remote resource loaders are
registered by this extractor.
