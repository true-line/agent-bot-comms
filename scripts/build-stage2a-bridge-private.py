#!/usr/bin/env python3
"""Build, sign, and notarize a private Darwin Stage 2a B bridge artifact.

Run only after the reviewed bridge source is on protected main and tagged.
The output parent must be a private directory outside this checkout. Nothing
from this command is uploaded to a public release or GitHub Actions artifact.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


TEAM_ID = "Z5DM34QS5U"
REPOSITORY = "https://github.com/true-line/agent-bot-comms.git"
BINARY_NAME = "agent-comms-stage2a-bridge"
SIGNING_ID = "ai.true-line.agent-bot-comms.stage2a-bridge"
ARGV = ["--assignment-fd", "3", "--proof-fd", "4", "--status-fd", "5"]
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


def run(*args, cwd=None, env=None, input=None):
    return subprocess.run(
        args, cwd=cwd, env=env, input=input, text=True, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def fail(message):
    raise ValueError(message)


def source_check(root, tag, source_sha):
    if not SHA_RE.fullmatch(source_sha):
        fail("source SHA must be a full lowercase commit hash")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        fail("tag must be vX.Y.Z")
    if run("git", "remote", "get-url", "origin", cwd=root) != REPOSITORY:
        fail("unexpected origin URL")
    if run("git", "status", "--porcelain=v1", "--untracked-files=all", cwd=root):
        fail("source checkout is not clean")
    if run("git", "rev-parse", "HEAD", cwd=root) != source_sha:
        fail("HEAD does not match reviewed source SHA")
    if run("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}", cwd=root) != source_sha:
        fail("local release tag does not resolve to reviewed source SHA")
    remote_tag = run(
        "git", "ls-remote", "--exit-code", "--tags", "origin",
        f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}", cwd=root,
    ).splitlines()
    remote_sha = {line.split("\t", 1)[1]: line.split("\t", 1)[0] for line in remote_tag}
    if remote_sha.get(f"refs/tags/{tag}^{{}}", remote_sha.get(f"refs/tags/{tag}")) != source_sha:
        fail("remote release tag does not resolve to reviewed source SHA")
    run("git", "fetch", "--no-tags", "origin", "main", cwd=root)
    run("git", "merge-base", "--is-ancestor", source_sha, "FETCH_HEAD", cwd=root)


def toolchain_check(go_version, sdk_version, clang_version):
    actual_go = run("go", "version")
    if actual_go != f"go version {go_version} darwin/arm64":
        fail(f"Go version/host differs from reviewed {go_version} darwin/arm64")
    actual_sdk = run("xcrun", "--sdk", "macosx", "--show-sdk-version")
    if actual_sdk != sdk_version:
        fail(f"macOS SDK differs from reviewed {sdk_version}")
    actual_clang = run("xcrun", "clang", "--version").splitlines()[0]
    if actual_clang != clang_version:
        fail("Apple clang differs from reviewed version")
    return run("xcrun", "--sdk", "macosx", "--show-sdk-path")


def selected_identity(keychain):
    identities = run("security", "find-identity", "-v", "-p", "codesigning", str(keychain))
    matching = re.findall(
        rf"^\s*\d+\)\s+([0-9A-F]{{40}})\s+\"Developer ID Application: [^\n]*\({TEAM_ID}\)\"$",
        identities, re.MULTILINE,
    )
    if len(matching) != 1:
        fail("expected exactly one Developer ID Application identity for the approved team")
    return matching[0]


def check_binary(binary):
    if run("lipo", "-archs", str(binary)) != "arm64":
        fail("bridge must be arm64-only")
    dependencies = []
    for line in run("otool", "-L", str(binary)).splitlines()[1:]:
        library = line.strip().split(" (", 1)[0]
        if not library.startswith(("/usr/lib/", "/System/Library/")):
            fail("bridge has a non-system dynamic dependency")
        dependencies.append(library)
    if not dependencies:
        fail("missing dynamic dependency inventory")
    run("codesign", "--verify", "--strict", "--verbose=2", str(binary))
    details = subprocess.run(
        ["codesign", "-dv", "--verbose=2", str(binary)],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stderr
    for expected in (
        "Authority=Developer ID Application: ",
        f"TeamIdentifier={TEAM_ID}\n",
        f"Identifier={SIGNING_ID}\n",
        "flags=0x10000(runtime)",
    ):
        if expected not in details:
            fail("signed bridge identity or hardened runtime does not match reviewed input")
    return dependencies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="reviewed Comms release tag, vX.Y.Z")
    parser.add_argument("--source-sha", required=True, help="reviewed full source commit SHA")
    parser.add_argument("--go-version", required=True, help="reviewed Go version, e.g. go1.27.4")
    parser.add_argument("--sdk-version", required=True, help="reviewed macOS SDK version")
    parser.add_argument("--clang-version", required=True, help="reviewed first line of Apple clang --version")
    parser.add_argument("--sign-keychain", required=True, type=Path)
    parser.add_argument("--notary-profile", required=True, help="existing notarytool Keychain profile")
    parser.add_argument("--output-dir", required=True, type=Path, help="new private artifact directory")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.expanduser().absolute()
    parent = output.parent.resolve(strict=True)
    if output.exists() or output.is_symlink():
        fail("output directory already exists")
    if root == parent or root in parent.parents:
        fail("output must be outside the source checkout")
    parent_stat = parent.stat()
    if parent_stat.st_uid != os.getuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
        fail("output parent must be owned by this user and mode 0700")
    keychain = args.sign_keychain.expanduser().resolve(strict=True)
    source_check(root, args.tag, args.source_sha)
    sdk_path = toolchain_check(args.go_version, args.sdk_version, args.clang_version)
    identity = selected_identity(keychain)
    os.umask(0o077)
    temporary = Path(tempfile.mkdtemp(prefix=".stage2a-bridge-", dir=parent))
    try:
        binary = temporary / BINARY_NAME
        build_env = {
            "PATH": os.environ["PATH"], "HOME": os.environ["HOME"],
            "GOOS": "darwin", "GOARCH": "arm64", "CGO_ENABLED": "1",
            "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off",
            "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "",
            "SDKROOT": sdk_path, "CC": run("xcrun", "--find", "clang"),
        }
        run(
            "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=true",
            "-ldflags=-buildid=", "-o", str(binary), ".",
            cwd=root / "native/stage2a-bridge", env=build_env,
        )
        build_info = run("go", "version", "-m", str(binary))
        if f"vcs.revision={args.source_sha}" not in build_info or "vcs.modified=false" not in build_info:
            fail("Go build metadata does not bind the clean reviewed source")
        unsigned_sha = digest(binary)
        run(
            "codesign", "--force", "--timestamp", "--options", "runtime",
            "--keychain", str(keychain), "-s", identity,
            "-i", SIGNING_ID, str(binary),
        )
        dependencies = check_binary(binary)
        signed_sha = digest(binary)
        archive = temporary / f"{BINARY_NAME}-{args.tag}-darwin-arm64.zip"
        run("ditto", "-c", "-k", str(binary), str(archive))
        extracted = temporary / "extracted"
        extracted.mkdir(mode=0o700)
        run("ditto", "-x", "-k", str(archive), str(extracted))
        if digest(extracted / BINARY_NAME) != signed_sha:
            fail("archived binary differs from signed binary")
        shutil.rmtree(extracted)
        notarization = json.loads(run(
            "xcrun", "notarytool", "submit", str(archive),
            "--keychain-profile", args.notary_profile,
            "--wait", "--timeout", "30m", "--output-format", "json",
        ))
        if notarization.get("status") != "Accepted" or not notarization.get("id"):
            fail("Apple notarization did not return Accepted with a request ID")
        manifest = {
            "schemaVersion": 1,
            "repository": REPOSITORY,
            "releaseTag": args.tag,
            "sourceCommit": args.source_sha,
            "sourceTree": run("git", "rev-parse", "HEAD^{tree}", cwd=root),
            "goVersion": args.go_version,
            "macosSdkVersion": args.sdk_version,
            "macosSdkPath": sdk_path,
            "appleClangVersion": args.clang_version,
            "goBuildInfo": build_info.splitlines(),
            "architecture": "arm64",
            "dynamicDependencies": dependencies,
            "teamId": TEAM_ID,
            "signingIdentifier": SIGNING_ID,
            "binaryName": BINARY_NAME,
            "binarySha256BeforeSigning": unsigned_sha,
            "binarySha256": signed_sha,
            "archiveName": archive.name,
            "archiveSha256": digest(archive),
            "notarizationRequestId": notarization["id"],
            "notarizationStatus": notarization["status"],
            "fixedArgv": ARGV,
            "environment": {},
            "installationAndLaunchVerified": False,
        }
        (temporary / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, output)
        print(json.dumps({"outputDir": str(output), "binarySha256": signed_sha, "archiveSha256": manifest["archiveSha256"]}))
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # Tool stderr can contain host-specific details; keep failures terse.
        print(f"private bridge build failed: {type(error).__name__}: {error if isinstance(error, ValueError) else 'inspect local tool state'}", file=sys.stderr)
        sys.exit(1)
