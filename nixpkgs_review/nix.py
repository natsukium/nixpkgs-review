import concurrent.futures
import functools
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from sys import platform
from tempfile import NamedTemporaryFile
from typing import Any, Final

from .allow import AllowedFeatures
from .errors import NixpkgsReviewError
from .utils import ROOT, System, info, sh, warn


@dataclass
class Attr:
    name: str
    exists: bool
    broken: bool
    blacklisted: bool
    path: Path | None
    drv_path: str | None
    aliases: list[str] = field(default_factory=list)
    log_url: str | None = field(default=None)
    build_err_msg: str | None = field(default=None)
    _path_verified: bool | None = field(init=False, default=None)

    def was_build(self) -> bool:
        if self.path is None:
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
            check=False,
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
    attrs_per_system: dict[System, list[str]],
    cache_directory: Path,
    local_system: str,
    build_graph: str,
    nix_path: str,
    nixpkgs_config: Path,
    nixpkgs_overlay: Path,
    run: str | None = None,
    sandbox: bool = False,
) -> None:
    nix_shell = shutil.which(build_graph + "-shell")
    if not nix_shell:
        msg = f"{build_graph} not found in PATH"
        raise RuntimeError(msg)

    shell_file_args = build_shell_file_args(
        cache_dir=cache_directory,
        attrs_per_system=attrs_per_system,
        local_system=local_system,
        nixpkgs_config=nixpkgs_config,
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
        msg = "Sandbox mode is only available on Linux platforms."
        raise RuntimeError(msg)

    bwrap = shutil.which("bwrap")
    if not bwrap:
        msg = "bwrap not found in PATH. Install it to use '--sandbox' flag."
        raise RuntimeError(msg)

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

    def tmpfs(path: Path | str, is_dir: bool = True) -> list[str]:
        dir_cmd = []
        if is_dir:
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
        *tmpfs("/tmp"),  # noqa: S108
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
        *bind("/tmp/.X11-unix", try_=True),  # noqa: S108
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
    blacklist = {
        "appimage-run-tests",
        "darwin.builder",
        "nixos-install-tools",
        "tests.nixos-functions.nixos-test",
        "tests.nixos-functions.nixosTest-test",
        "tests.php.overrideAttrs-preserves-enabled-extensions",
        "tests.php.withExtensions-enables-previously-disabled-extensions",
        "tests.trivial",
        "tests.writers",
    }
    attr_by_path: dict[Path, Attr] = {}
    broken = []
    for name, props in json.items():
        path = props.get("path", None)
        if path is not None:
            path = Path(path)

        attr = Attr(
            name=name,
            exists=props["exists"],
            broken=props["broken"],
            blacklisted=name in blacklist,
            path=path,
            drv_path=props["drvPath"],
        )
        if attr.path is not None:
            other = attr_by_path.get(attr.path, None)
            if other is None:
                attr_by_path[attr.path] = attr
            elif len(other.name) > len(attr.name):
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
) -> list[Attr]:
    attr_json = NamedTemporaryFile(mode="w+", delete=False)  # noqa: SIM115
    delete = True
    try:
        json.dump(list(attrs), attr_json)
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

        nix_eval = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=False)
        if nix_eval.returncode != 0:
            delete = False
            msg = (
                f"{' '.join(cmd)} failed to run, {attr_json.name} was stored inspection"
            )
            raise NixpkgsReviewError(msg)

        return _nix_eval_filter(json.loads(nix_eval.stdout))
    finally:
        attr_json.close()
        if delete:
            Path(attr_json.name).unlink()


def multi_system_eval(
    attr_names_per_system: dict[System, set[str]],
    allow: AllowedFeatures,
    nix_path: str,
    n_threads: int,
) -> dict[System, list[Attr]]:
    results: dict[System, list[Attr]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as executor:
        future_to_system = {
            executor.submit(
                nix_eval,
                attrs=attrs,
                system=system,
                allow=allow,
                nix_path=nix_path,
            ): system
            for system, attrs in attr_names_per_system.items()
        }
        for future in concurrent.futures.as_completed(future_to_system):
            system = future_to_system[future]
            results[system] = future.result()

    return results


def nix_build(
    attr_names_per_system: dict[System, set[str]],
    args: str,
    cache_directory: Path,
    local_system: System,
    allow: AllowedFeatures,
    build_graph: str,
    nix_path: str,
    nixpkgs_config: Path,
    n_threads: int,
) -> dict[System, list[Attr]]:
    if not attr_names_per_system:
        info("Nothing to be built.")
        return {}

    attrs_per_system: dict[System, list[Attr]] = multi_system_eval(
        attr_names_per_system,
        allow,
        nix_path,
        n_threads=n_threads,
    )

    filtered_per_system: dict[System, list[str]] = {}
    for system, attrs in attrs_per_system.items():
        filtered_per_system[system] = []
        for attr in attrs:
            if not (attr.broken or attr.blacklisted):
                filtered_per_system[system].append(attr.name)

    if all(len(filtered) == 0 for filtered in filtered_per_system.values()):
        return attrs_per_system

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
        cache_dir=cache_directory,
        attrs_per_system=filtered_per_system,
        local_system=local_system,
        nixpkgs_config=nixpkgs_config,
    ) + shlex.split(args)

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
    for line in stderr.splitlines():
        if "dependencies couldn't be built" in line:
            has_failed_dependencies.append(
                next(item for item in line.split() if nix_store in item)
                .lstrip("'")
                .rstrip(":'")
            )

    drv_path_to_attr = {
        a.drv_path: a for _, attrs in attrs_per_system.items() for a in attrs
    }

    for drv_path in has_failed_dependencies:
        if drv_path in drv_path_to_attr:
            attr = drv_path_to_attr[drv_path]
            attr.build_err_msg = stderr

    return attrs_per_system


def build_shell_file_args(
    cache_dir: Path,
    attrs_per_system: dict[System, list[str]],
    local_system: str,
    nixpkgs_config: Path,
) -> list[str]:
    attrs_file = cache_dir.joinpath("attrs.nix")
    with attrs_file.open("w+") as f:
        f.write("{\n")
        for system, attrs in attrs_per_system.items():
            f.write(f"  {system} = [\n")
            for attr in attrs:
                f.write(f'    "{attr}"\n')
            f.write("  ];\n")
        f.write("}")
        print(f.read())

    return [
        "--argstr",
        "local-system",
        local_system,
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
