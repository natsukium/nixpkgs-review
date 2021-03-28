import functools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from sys import platform
from tempfile import NamedTemporaryFile
from typing import Any, Final

from .allow import AllowedFeatures
from .errors import NixpkgsReviewError
from .utils import ROOT, escape_attr, info, sh, warn


@dataclass
class Attr:
    name: str
    exists: bool
    broken: bool
    blacklisted: bool
    skipped: bool
    path: str | None
    drv_path: str | None
    position: str | None
    log_url: str | None = field(default=None)
    aliases: list[str] = field(default_factory=lambda: [])
    timed_out: bool = field(default=False)
    build_err_msg: str | None = field(default=None)
    _path_verified: bool | None = field(init=False, default=None)

    def was_build(self) -> bool:
        if self.path is None:
            return False

        if self.skipped:
            return False

        if self._path_verified is not None:
            return self._path_verified

        res = subprocess.run(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command",
                "store",
                "verify",
                "--no-contents",
                "--no-trust",
                self.path,
            ],
            stderr=subprocess.DEVNULL,
        )
        self._path_verified = res.returncode == 0
        return self._path_verified

    def is_test(self) -> bool:
        return self.name.startswith("nixosTests")

    def log(self, tail: int = -1, strip_colors: bool = False) -> str | None:
        def get_log(path: str | None) -> str | None:
            if path is None:
                return None
            system = subprocess.run(
                ["nix", "--experimental-features", "nix-command", "log", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="backslashreplace",
            )
            stdout = system.stdout
            if tail > 0 and len(stdout) > tail:
                stdout = "This file has been truncated\n" + stdout[-tail:]

            if strip_colors:
                return strip_ansi_colors(stdout)
            return stdout

        if self.drv_path is None:
            return None

        value = get_log(self.drv_path) or get_log(self.path) or ""
        if self.build_err_msg is not None:
            value = "\n".join([value, self.build_err_msg])

        return value

    def log_path(self) -> str | None:
        if self.drv_path is None:
            return None
        base = os.path.basename(self.drv_path)

        # TODO: On non-default configurations of nix, the logs
        # could be stored in a different directory. We lack a
        # robust way to discover this, which will prevent this
        # function from finding the path (currently used only to
        # determine the build time).
        prefix = "/nix/var/log/nix/drvs/"
        candidate_paths = (
            os.path.join(prefix, base[:2], base[2:] + ".bz2"),
            os.path.join(prefix, base[:2], base[2:]),
        )
        for path in candidate_paths:
            if os.path.isfile(path):
                return path
        return None

    def build_time(self) -> timedelta | None:
        log_path = self.log_path()
        if log_path is None:
            return None

        proc = subprocess.run(
            ["stat", "--format", "%W %Y", log_path],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode == 0:
            birthtime, mtime = map(int, proc.stdout.split())
            if birthtime != 0:
                return timedelta(seconds=(mtime - birthtime))
        return None


REVIEW_SHELL: Final[str] = str(ROOT.joinpath("nix/review-shell.nix"))


def nix_shell(
    attrs: list[str],
    cache_directory: Path,
    system: str,
    build_graph: str,
    nix_path: str,
    nixpkgs_config: Path,
    nixpkgs_overlay: Path,
    run: str | None = None,
    sandbox: bool = False,
) -> None:
    nix_shell = shutil.which(build_graph + "-shell")
    if not nix_shell:
        raise RuntimeError(f"{build_graph} not found in PATH")

    shell_file_args = build_shell_file_args(
        cache_directory, attrs, system, nixpkgs_config
    )
    if sandbox:
        args = _nix_shell_sandbox(
            nix_shell,
            shell_file_args,
            cache_directory,
            nix_path,
            nixpkgs_config,
            nixpkgs_overlay,
        )
    else:
        args = [nix_shell, *shell_file_args, "--nix-path", nix_path, REVIEW_SHELL]
    if run:
        args.extend(["--run", run])
    sh(args, cwd=cache_directory)


def _nix_shell_sandbox(
    nix_shell: str,
    shell_file_args: list[str],
    cache_directory: Path,
    nix_path: str,
    nixpkgs_config: Path,
    nixpkgs_overlay: Path,
) -> list[str]:
    if platform != "linux":
        raise RuntimeError("Sandbox mode is only available on Linux platforms.")

    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError(
            "bwrap not found in PATH. Install it to use '--sandbox' flag."
        )

    warn("Using sandbox mode. Some things may break!")

    def bind(
        path: Path | str,
        ro: bool = True,
        dev: bool = False,
        try_: bool = False,
    ) -> list[str]:
        if dev:
            prefix = "--dev-"
        elif ro:
            prefix = "--ro-"
        else:
            prefix = "--"

        suffix = "-try" if try_ else ""

        return [prefix + "bind" + suffix, str(path), str(path)]

    def tmpfs(path: Path | str, dir: bool = True) -> list[str]:
        dir_cmd = []
        if dir:
            dir_cmd = ["--dir", str(path)]

        return [*dir_cmd, "--tmpfs", str(path)]

    nixpkgs_review_pr = cache_directory
    home = Path.home()
    current_dir = Path().absolute()
    xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", home.joinpath(".config")))
    nixpkgs_config_dir = xdg_config_home.joinpath("nixpkgs")
    xauthority = Path(os.environ.get("XAUTHORITY", home.joinpath(".Xauthority")))
    hub_config = xdg_config_home.joinpath("hub")
    gh_config = xdg_config_home.joinpath("gh")

    uid = os.environ.get("UID", "1000")

    bwrap_args = [
        "--die-with-parent",
        "--unshare-cgroup",
        "--unshare-ipc",
        "--unshare-uts",
        # / and cia.
        *bind("/"),
        *bind("/dev", dev=True),
        *tmpfs("/tmp"),
        # Required for evaluation
        *bind(nixpkgs_config),
        *bind(nixpkgs_overlay),
        # /run (also cover sockets for wayland/pulseaudio and pipewires)
        *bind(Path("/run/user").joinpath(uid), dev=True, try_=True),
        # HOME
        *tmpfs(home),
        *bind(current_dir, ro=False),
        *bind(nixpkgs_review_pr, ro=False),
        *bind(nixpkgs_config_dir, try_=True),
        # For X11 applications
        *bind("/tmp/.X11-unix", try_=True),
        *bind(xauthority, try_=True),
        # GitHub
        *bind(hub_config, try_=True),
        *bind(gh_config, try_=True),
    ]
    return [
        bwrap,
        *bwrap_args,
        "--",
        nix_shell,
        *shell_file_args,
        REVIEW_SHELL,
        "--nix-path",
        nix_path,
    ]


def _nix_eval_filter(json: dict[str, Any]) -> list[Attr]:
    # workaround https://github.com/NixOS/ofborg/issues/269
    blacklist = set(
        [
            "appimage-run-tests",
            "darwin.builder",
            "nixos-install-tools",
            "tests.nixos-functions.nixos-test",
            "tests.nixos-functions.nixosTest-test",
            "tests.php.overrideAttrs-preserves-enabled-extensions",
            "tests.php.withExtensions-enables-previously-disabled-extensions",
            "tests.trivial",
            "tests.writers",
        ]
    )
    attr_by_path: dict[str, Attr] = {}
    broken = []

    for name, props in json.items():
        attr = Attr(
            name=name,
            exists=props["exists"],
            broken=props["broken"],
            blacklisted=name in blacklist,
            skipped=False,
            path=props["path"],
            drv_path=props["drvPath"],
            position=props["position"] if props["position"] is not None else None,
        )
        if attr.path is not None:
            other = attr_by_path.get(attr.path, None)
            if other is None:
                attr_by_path[attr.path] = attr
            else:
                if len(other.name) > len(attr.name):
                    attr_by_path[attr.path] = attr
                    attr.aliases.append(other.name)
                else:
                    other.aliases.append(attr.name)
        else:
            broken.append(attr)
    return list(attr_by_path.values()) + broken


def nix_eval(
    attrs: set[str],
    system: str,
    allow: AllowedFeatures,
    nix_path: str,
    cache_directory: Path | None = None,
) -> list[Attr]:
    def _eval(attrs: list[str]) -> dict[str, Any]:
        attr_json = NamedTemporaryFile(mode="w+", delete=False)
        delete = True
        try:
            json.dump(attrs, attr_json)
            eval_script = str(ROOT.joinpath("nix/evalAttrs.nix"))
            attr_json.flush()
            cmd = [
                "nix",
                "--extra-experimental-features",
                "nix-command" if allow.url_literals else "nix-command no-url-literals",
                "--system",
                system,
                "eval",
                "--nix-path",
                nix_path,
                "--json",
                "--impure",
                "--allow-import-from-derivation"
                if allow.ifd
                else "--no-allow-import-from-derivation",
                "--expr",
                f"(import {eval_script} {{ attr-json = {attr_json.name}; }})",
            ]

            nix_eval = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
            if nix_eval.returncode != 0:
                delete = False
                raise NixpkgsReviewError(
                    f"{' '.join(cmd)} failed to run, {attr_json.name} was stored inspection"
                )

            return json.loads(nix_eval.stdout)
        finally:
            attr_json.close()
            if delete:
                os.unlink(attr_json.name)

    #
    # Split the evaluation into chunks of 4096 attrs at a time.
    # This helps limit the memory usage, which can be a problem.
    #
    start_time = time.time()
    eval_data = {}
    attrlist = sorted(attrs)
    MAX_ATTRS_AT_ONCE = 4096

    for i in range(0, len(attrs), MAX_ATTRS_AT_ONCE):
        chunk = attrlist[i : i + MAX_ATTRS_AT_ONCE]
        eval_data.update(_eval(chunk))

    if cache_directory is not None:
        # This information contains a lot of details about each attr, and may
        # be used by scripts that run inside the nixpkgs-review shell.
        with open(cache_directory.joinpath("changed-attrs.json"), "w") as f:
            json.dump(eval_data, f)

    if time.time() - start_time > 30:
        info(f"Time required for nix eval: {time.time() - start_time:.0f} sec")

    return _nix_eval_filter(eval_data)


def nix_build(
    attr_names: set[str],
    args: str,
    cache_directory: Path,
    system: str,
    allow: AllowedFeatures,
    build_graph: str,
    nix_path: str,
    nixpkgs_config: Path,
) -> list[Attr]:
    if not attr_names:
        info("Nothing to be built.")
        return []

    attrs = nix_eval(
        attr_names, system, allow, nix_path, cache_directory=cache_directory
    )
    attrs = pre_build_filter(attrs, cache_directory=cache_directory)
    filtered = []
    for attr in attrs:
        if not (attr.broken or attr.blacklisted or attr.skipped):
            filtered.append(attr.name)

    if len(filtered) == 0:
        return attrs

    command = [
        build_graph,
        "build",
        "--file",
        REVIEW_SHELL,
        "--nix-path",
        nix_path,
        "--extra-experimental-features",
        "nix-command" if allow.url_literals else "nix-command no-url-literals",
        "--no-link",
        "--keep-going",
        "--allow-import-from-derivation"
        if allow.ifd
        else "--no-allow-import-from-derivation",
    ]

    if platform == "linux":
        command += [
            # only matters for single-user nix and trusted users
            "--option",
            "build-use-sandbox",
            "relaxed",
        ]

    command += build_shell_file_args(
        cache_directory, filtered, system, nixpkgs_config
    ) + shlex.split(args)

    sh(command)
    proc = sh(command, stderr=subprocess.PIPE)
    stderr = proc.stderr
    # Remove boring 'copying path' lines from stderr
    nix_store = _store_dir()
    stderr = "\n".join(
        line
        for line in stderr.splitlines()
        if not (line.startswith("copying path '") and line.endswith("..."))
    )

    has_failed_dependencies = []
    has_timeout = {}
    for line in stderr.splitlines():
        if "dependencies couldn't be built" in line:
            has_failed_dependencies.append(
                next(item for item in line.split() if nix_store in item)
                .lstrip("'")
                .rstrip(":'")
            )
        if "timed out after" in line:
            drv = next(item for item in line.split() if nix_store in item).strip("'")
            has_timeout[drv] = line

    drv_path_to_attr = {a.drv_path: a for a in attrs}
    for drv_path in has_timeout.keys():
        if drv_path in drv_path_to_attr:
            attr = drv_path_to_attr[drv_path]
            attr.build_err_msg = has_timeout[drv_path]
            attr.timed_out = True

    for drv_path in has_failed_dependencies:
        if drv_path in drv_path_to_attr:
            attr = drv_path_to_attr[drv_path]
            attr.build_err_msg = stderr

            # Without inspecting the build graph, let's just guess
            # that if something failed to build and there were ANY timeouts
            # that it's probably the case that this failure to build
            # was probably caused by the timeout.
            # e.g. https://github.com/NixOS/nixpkgs/pull/114609
            if len(has_timeout) > 0:
                attr.timed_out = True

    return attrs


def pre_build_filter(attrs: list[Attr], cache_directory: Path) -> list[Attr]:
    for cmd in (
        cmd
        for cmd in os.environ.get("NIXPKGS_REVIEW_PRE_BUILD_FILTER", "").split(":")
        if cmd
    ):
        encoded = json.dumps(
            {
                "attrs": [attr.__dict__ for attr in attrs],
            }
        )
        p = sh(
            [cmd],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=sys.stdout,
            cwd=cache_directory.as_posix(),
        )
        attrs = [Attr(**arg) for arg in json.loads(p.stdout)]
    return attrs


def build_shell_file_args(
    cache_dir: Path, attrs: list[str], system: str, nixpkgs_config: Path
) -> list[str]:
    attrs_file = cache_dir.joinpath("attrs.nix")
    with open(attrs_file, "w+", encoding="utf-8") as f:
        f.write("pkgs: with pkgs; [\n")
        f.write("\n".join(f"  {escape_attr(a)}" for a in attrs))
        f.write("\n]")

    return [
        "--argstr",
        "system",
        system,
        "--argstr",
        "nixpkgs-path",
        str(cache_dir.joinpath("nixpkgs/")),
        "--argstr",
        "nixpkgs-config-path",
        str(nixpkgs_config),
        "--argstr",
        "attrs-path",
        str(attrs_file),
    ]


def strip_ansi_colors(s: str) -> str:
    # https://stackoverflow.com/a/14693789/1079728
    # 7-bit C1 ANSI sequences
    ansi_escape = re.compile(
        r"""
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by a control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    """,
        re.VERBOSE,
    )
    return ansi_escape.sub("", s)


@functools.lru_cache()
def _store_dir() -> str:
    return subprocess.check_output(
        [
            "nix",
            "--experimental-features",
            "nix-command",
            "eval",
            "--raw",
            "--expr",
            "(builtins.storeDir)",
        ],
        text=True,
    )
