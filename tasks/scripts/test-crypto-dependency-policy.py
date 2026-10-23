# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise the real cargo-deny policy with tiny, offline Cargo package graphs.

No crypto code is built or downloaded. Package names and dependency edges are
enough to check that an approved wrapper cannot mask an application bypass.
"""

import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "deny.toml"


def check_graph(
    directory: Path,
    edges: list[tuple[str, str, str, str]],
    banned: str | None = None,
) -> None:
    """Each edge is (parent, package, manifest section, dependency alias)."""
    packages = {name for parent, child, _, _ in edges for name in (parent, child)}
    members = {
        name
        for name in packages
        if name.startswith("openshell-") or name == "policy-test-app"
    }
    directory.mkdir()
    (directory / "Cargo.toml").write_text(
        '[workspace]\nresolver = "2"\nmembers = '
        + json.dumps(sorted(members))
        + "\nexclude = "
        + json.dumps(sorted(packages - members))
        + "\n",
        encoding="utf-8",
    )
    for package in packages:
        source = directory / package / "src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text("", encoding="utf-8")
        manifest = (
            f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2021"\n'
        )
        sections: dict[str, list[str]] = {}
        for parent, child, section, alias in edges:
            if parent == package:
                sections.setdefault(section, []).append(
                    f'{alias} = {{ package = "{child}", path = "../{child}" }}'
                )
        for section, dependencies in sections.items():
            manifest += f"\n[{section}]\n" + "\n".join(dependencies) + "\n"
        (source.parent / "Cargo.toml").write_text(manifest, encoding="utf-8")

    result = subprocess.run(
        [
            "cargo",
            "deny",
            "--offline",
            "--color",
            "never",
            "--manifest-path",
            str(directory / "Cargo.toml"),
            "--config",
            str(POLICY),
            "check",
            "bans",
        ],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if banned is None:
        passed = result.returncode == 0
    else:
        # A metadata/configuration failure must not count as a successful ban.
        passed = (
            result.returncode != 0 and f"error[banned]: crate '{banned} =" in output
        )
    if not passed:
        raise AssertionError(f"{directory.name}: unexpected policy result\n{output}")
    print(f"PASS {directory.name}")


def edge(
    parent: str, child: str, section: str = "dependencies", alias: str = ""
) -> tuple[str, str, str, str]:
    return parent, child, section, alias or child


def main() -> None:
    facade = [
        edge("policy-test-app", "openshell-crypto"),
        edge("openshell-crypto", "aws-lc-rs"),
        edge("aws-lc-rs", "aws-lc-sys"),
        edge("aws-lc-rs", "aws-lc-fips-sys"),
        edge("openshell-crypto", "openssl"),
        edge("openssl", "openssl-sys"),
        edge("openshell-crypto", "rustls-openssl"),
        edge("rustls-openssl", "openssl"),
        edge("rustls-openssl", "openssl-sys"),
        edge("openshell-crypto", "jsonwebtoken-openssl"),
        edge("jsonwebtoken-openssl", "openssl"),
    ]
    with tempfile.TemporaryDirectory(prefix="openshell-crypto-policy-") as temp:
        root = Path(temp)
        check_graph(root / "facade-backends", facade)
        check_graph(
            root / "documented-exceptions",
            [
                edge("openshell-server", "rsa", "dev-dependencies"),
                edge("openshell-driver-vault", "sha2"),
                edge("policy-test-app", "russh"),
                edge("russh", "aes"),
                edge("policy-test-app", "rustls"),
                edge("rustls", "ring"),
            ],
        )
        # Keep the valid facade path present in every negative case. A shared
        # implementation must still reject each unapproved direct parent.
        for package in (
            "aws-lc-rs",
            "aws-lc-sys",
            "aws-lc-fips-sys",
            "openssl",
            "openssl-sys",
            "rustls-openssl",
            "jsonwebtoken-openssl",
            "ring",
            "sha2",
            "hmac",
            "aes-gcm",
            "rsa",
            "ed25519-dalek",
            "blake3",
            "ecdsa",
            "ml-kem",
        ):
            check_graph(
                root / f"direct-{package}",
                [*facade, edge("policy-test-app", package)],
                package,
            )
        for name, section in (
            ("renamed", "dependencies"),
            ("build", "build-dependencies"),
            ("dev", "dev-dependencies"),
            ("windows-only", "target.'cfg(windows)'.dependencies"),
        ):
            check_graph(
                root / name,
                [*facade, edge("policy-test-app", "openssl", section, "crypto_alias")],
                "openssl",
            )
        check_graph(
            root / "unapproved-wrapper",
            [
                *facade,
                edge("policy-test-app", "another-crypto-wrapper"),
                edge("another-crypto-wrapper", "openssl"),
            ],
            "openssl",
        )


if __name__ == "__main__":
    main()
