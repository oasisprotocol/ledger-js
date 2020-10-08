# Release Process

The following steps should be followed when preparing a release.

## Preparing a Regular Release

### Bump `package.json` Version

Before a release, make sure that you have bumped the `version` field in
`package.json` to the new version.

### Tag Next Release

Create a new signed git tag from the latest commit in origin remote's `master`
branch. The tag should be called `v<VERSION>` where `VERSION` corresponds to
the `version` field in `package.json`.

_TODO: Add Makefile target to make this easier._

### Ensure npm Release Was Published

After the tag with the next release is pushed to the [canonical git repository],
the GitHub Actions [Release manager workflow] is triggered which uses the
[yarn] tool to automatically build packages and publish the new release in the
npm registry.

Browse to [the npm registry] and make sure the new release is properly
published.

[canonical git repository]: https://github.com/oasisprotocol/ledger-js
[Release manager workflow]: ../.github/workflows/release.yml
[the npm registry]: https://www.npmjs.com/package/@oasisprotocol/ledger
