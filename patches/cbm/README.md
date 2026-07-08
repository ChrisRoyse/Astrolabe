# CBM Patch Policy

`vendor/codebase-memory-mcp` is the unmodified parent source for issue #1. Do
not patch files in that subtree directly for integration work.

If Astrolabe needs a CBM change before it can be upstreamed, add a patch file in
this directory and document:

- the CBM file or behavior it changes;
- the Astrolabe issue that requires it;
- the verification command proving the patched behavior;
- whether the patch is temporary or intended for upstream.
