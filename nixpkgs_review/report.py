import json
import os
import sys
import traceback
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from humanize import naturaldelta

from .github import GithubClient
from .nix import Attr
from .utils import System, info, link, skipped, system_order_key, warn


def print_number(
    packages: list[Attr],
    msg: str,
    what: str = "package",
    log: Callable[[str], None] = warn,
) -> None:
    if len(packages) == 0:
        return
    plural = "s" if len(packages) > 1 else ""
    names = (a.name for a in packages)
    log(f"{len(packages)} {what}{plural} {msg}:")
    log(" ".join(names))
    log("")


def html_pkgs_section(
    emoji: str, packages: list[Attr], msg: str, what: str = "package", show: int = -1
) -> str:
    if len(packages) == 0:
        return ""
    plural = "s" if len(packages) > 1 else ""

    res = "<details>\n"
    res += (
        f"  <summary>{emoji} {len(packages)} {what}{plural} {msg}:</summary>\n  <ul>\n"
    )
    for i, pkg in enumerate(packages):
        if show > 0 and i >= show:
            res += "    <li>...</li>\n"
            break

        if pkg.log_url is not None:
            res += f'    <li><a href="{pkg.log_url}">{pkg.name}</a>'
        else:
            res += f"    <li>{pkg.name}"
        if len(pkg.aliases) > 0:
            res += f" ({' ,'.join(pkg.aliases)})"
        res += "</li>\n"
    res += "  </ul>\n</details>\n"
    return res


class LazyDirectory:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.created = False

    def ensure(self) -> Path:
        if not self.created:
            self.path.mkdir(exist_ok=True)
            self.created = True
        return self.path


def write_result_links(
    attrs_per_system: dict[str, list[Attr]], directory: Path
) -> None:
    results = LazyDirectory(directory.joinpath("results"))
    failed_results = LazyDirectory(directory.joinpath("failed_results"))
    for system, attrs in attrs_per_system.items():
        for attr in attrs:
            # Broken attrs have no drv_path.
            if attr.blacklisted or attr.drv_path is None:
                continue

            attr_name: str = f"{attr.name}-{system}"

            if attr.path is not None and attr.path.exists():
                if attr.was_build():
                    symlink_source = results.ensure().joinpath(attr_name)
                else:
                    symlink_source = failed_results.ensure().joinpath(attr_name)
                if os.path.lexists(symlink_source):
                    symlink_source.unlink()
                symlink_source.symlink_to(attr.path)


def _serialize_attrs(attrs: list[Attr]) -> list[str]:
    return [a.name for a in attrs]


class SystemReport:
    def __init__(self, attrs: list[Attr]) -> None:
        self.broken: list[Attr] = []
        self.failed: list[Attr] = []
        self.non_existent: list[Attr] = []
        self.blacklisted: list[Attr] = []
        self.tests: list[Attr] = []
        self.built: list[Attr] = []

        for attr in attrs:
            if attr.broken:
                self.broken.append(attr)
            elif attr.blacklisted:
                self.blacklisted.append(attr)
            elif not attr.exists:
                self.non_existent.append(attr)
            elif attr.name.startswith("nixosTests."):
                self.tests.append(attr)
            elif not attr.was_build():
                self.failed.append(attr)
            else:
                self.built.append(attr)

    def serialize(self) -> dict[str, list[str]]:
        return {
            "broken": _serialize_attrs(self.broken),
            "non-existent": _serialize_attrs(self.non_existent),
            "blacklisted": _serialize_attrs(self.blacklisted),
            "failed": _serialize_attrs(self.failed),
            "built": _serialize_attrs(self.built),
            "tests": _serialize_attrs(self.tests),
        }


def order_reports(reports: dict[System, SystemReport]) -> dict[System, SystemReport]:
    """Ensure that systems are always ordered consistently in reports"""
    return dict(
        sorted(
            reports.items(),
            key=lambda item: system_order_key(system=item[0]),
            reverse=True,
        )
    )


def write_error_logs(
    system_report_per_system: dict[System, SystemReport], directory: Path
) -> None:
    logs = LazyDirectory(directory.joinpath("logs"))

    for system, system_report in system_report_per_system.items():
        for attr in system_report.failed:
            attr_name: str = f"{attr.name}-{system}"
            with open(
                logs.ensure().joinpath(attr_name + ".log"), "w+", encoding="utf-8"
            ) as f:
                log_content = attr.log()
                if log_content is not None:
                    f.write(log_content)


class Report:
    def __init__(
        self,
        attrs_per_system: dict[str, list[Attr]],
        extra_nixpkgs_config: str,
        show_header: bool = True,
        *,
        checkout: Literal["merge", "commit"] = "merge",
    ) -> None:
        self.show_header = show_header
        self.attrs = attrs_per_system
        self.checkout = checkout

        if extra_nixpkgs_config != "{ }":
            self.extra_nixpkgs_config: str | None = extra_nixpkgs_config
        else:
            self.extra_nixpkgs_config = None

        reports: dict[System, SystemReport] = {}
        for system, attrs in attrs_per_system.items():
            reports[system] = SystemReport(attrs)
        self.system_reports: dict[System, SystemReport] = order_reports(reports)

    def built_packages(self) -> dict[System, list[str]]:
        return {
            system: [a.name for a in report.built]
            for system, report in self.system_reports.items()
        }

    def write(self, directory: Path, pr: int | None) -> None:
        directory.joinpath("report.md").write_text(self.markdown(pr))
        directory.joinpath("report.json").write_text(self.json(pr))

        write_result_links(self.attrs, directory)
        write_error_logs(self.system_reports, directory)

    def succeeded(self) -> bool:
        """Whether the report is considered a success or a failure"""
        return all((len(report.failed) == 0) for report in self.system_reports.values())

    def upload_build_logs(self, github_client: GithubClient, pr: int | None) -> None:
        for system, reports in self.system_reports.items():
            for pkg in reports.failed:
                log_content = pkg.log(tail=1 * 1024 * 1014, strip_colors=True)
                build_time = pkg.build_time()
                description = f"system: {system}"
                if build_time is not None:
                    description += f" | build_time: {naturaldelta(build_time)}"
                if pr is not None:
                    description += f" | https://github.com/NixOS/nixpkgs/pull/{pr}"

                if log_content is not None and len(log_content) > 0:
                    try:
                        gist = github_client.upload_gist(
                            name=pkg.name, content=log_content, description=description
                        )
                        pkg.log_url = gist["html_url"]
                    except urllib.error.HTTPError:
                        # This is possible due to rate-limiting or a failure of that sort.
                        # It should not be fatal.
                        traceback.print_exc(file=sys.stderr)
                else:
                    print(f"Log content for {pkg} was empty", file=sys.stderr)

    def json(self, pr: int | None) -> str:
        return json.dumps(
            {
                "systems": list(self.system_reports.keys()),
                "pr": pr,
                "checkout": self.checkout,
                "extra-nixpkgs-config": self.extra_nixpkgs_config,
                "result": {
                    system: report.serialize()
                    for system, report in self.system_reports.items()
                },
            },
            sort_keys=True,
            indent=4,
        )

    def markdown(self, pr: int | None) -> str:
        msg = ""
        if self.show_header:
            msg += "## `nixpkgs-review` result\n\n"
            msg += "Generated using [`nixpkgs-review`](https://github.com/Mic92/nixpkgs-review).\n\n"

            cmd = "nixpkgs-review"
            if pr is not None:
                cmd += f" pr {pr}"
            if self.extra_nixpkgs_config:
                cmd += f" --extra-nixpkgs-config '{self.extra_nixpkgs_config}'"
            if self.checkout != "merge":
                cmd += f" --checkout {self.checkout}"
            msg += f"Command: `{cmd}`\n"

        for system, report in self.system_reports.items():
            msg += "\n---\n"
            msg += f"### `{system}`\n"
            msg += html_pkgs_section(
                ":fast_forward:", report.broken, "marked as broken and skipped"
            )
            msg += html_pkgs_section(
                ":fast_forward:",
                report.non_existent,
                "present in ofBorgs evaluation, but not found in the checkout",
            )
            msg += html_pkgs_section(
                ":fast_forward:", report.blacklisted, "blacklisted"
            )
            msg += html_pkgs_section(":x:", report.failed, "failed to build")
            msg += html_pkgs_section(
                ":white_check_mark:", report.tests, "built", what="test"
            )
            msg += html_pkgs_section(":white_check_mark:", report.built, "built")

        return msg

    def print_console(self, pr: int | None) -> None:
        if pr is not None:
            pr_url = f"https://github.com/NixOS/nixpkgs/pull/{pr}"
            info("\nLink to currently reviewing PR:")
            link(f"\u001b]8;;{pr_url}\u001b\\{pr_url}\u001b]8;;\u001b\\\n")

        for system, report in self.system_reports.items():
            info(f"--------- Report for '{system}' ---------")
            print_number(report.broken, "marked as broken and skipped", log=skipped)
            print_number(
                report.non_existent,
                "present in ofBorgs evaluation, but not found in the checkout",
                log=skipped,
            )
            print_number(report.blacklisted, "blacklisted", log=skipped)
            print_number(report.failed, "failed to build")
            print_number(report.tests, "built", what="tests", log=print)
            print_number(report.built, "built", log=print)
