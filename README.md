# In-App Telemetry Python SDK

This is an In-App Telemetry Python SDK implemented entirely in Python. It exposes a more pythonic interface and relies on no C/C++ shared library.

## Version

The In-App Telemetry Python SDK is currently at version `1.0.0.0`.

## Configuration Notes

Version `1.0.0.0` uploads telemetry as SKR records. A few options are worth knowing about.

**`TelemetryId` is your application's own id,** provisioned by Governance and
baked into your build.

The policy lists the applications it supports. If your `TelemetryId` is not
among them, the SDK collects and uploads nothing, and `flush()` discards what
was recorded rather than queueing it for a retry that cannot succeed.

Setting `IASPYTHON_POLICY_TELEMETRY_ID` to a GUID points the SDK at that
policy document instead of the released one, for testing against a policy
that has not shipped yet:

```console
IASPYTHON_POLICY_TELEMETRY_ID=<dev-guid> python my_app.py
```

This is a development setting and is not for production. The SDK logs a
warning whenever it honors one, and ignores a value that is not a GUID.

**`CollectorUrl` is the full base URL of the collector.** The SDK appends only
`records` to it.

It is optional, and overrides the `_endpoint` the policy document supplies.
Leave it out to upload wherever the policy says, which is what the samples do
and what applications should do; set it only to point at a different
environment.

Note that leaving it out means the policy decides whether the SDK uploads at
all: a policy that supplies no `_endpoint` retires the agent, and recorded
data is then discarded rather than queued. `CollectorUrl` overrides that
decision, which is why the SDK's own tests set it.

It overrides the endpoint and nothing else. A flush still needs a policy to
load, so if none can be fetched or read from cache the data is saved to disk
and retried whatever `CollectorUrl` says. `_endpoint.backoff` still throttles
how often the SDK uploads, so a sample run twice in quick succession may not
upload the second time.

**TLS is always verified, and there is no option to turn it off.**

**On the async SDK, `attach_file()` must be awaited.** Everything that touches
the disk or the network is a coroutine in `iaspython.aio`, and
`attach_file()` is one of them — storing an attachment compresses and copies a
file that can be crash-dump sized, and that work runs on a worker thread so it
does not stall the event loop. The synchronous SDK is unaffected.

```python
# iaspython.aio
await telemetry.attach_file("AppLog", "app.log")
await telemetry.attach("Snapshot", payload)

# iaspython.sync
telemetry.attach_file("AppLog", "app.log")
```

Forgetting the `await` does not raise; Python creates the coroutine, never runs
it, and the attachment is silently never recorded. Python normally warns about
this — "coroutine ... was never awaited" — so treat that warning as an error.

**Attachments are stored uncompressed unless you ask.** Pass `compress=True` to
`attach()` or `attach_file()` to have the SDK compress that attachment before
it is stored and uploaded:

```python
telemetry.attach_file("AppLog", "app.log", compress=True)          # sync
await telemetry.attach_file("AppLog", "app.log", compress=True)    # async
```

The SDK writes the attachment's content encoding itself — the `ce` of its
story, `"zlib"` when compressed and `"raw"` when not. You do not set `ce`
yourself. Files that are already compressed (`.gz`,
`.zip`) are stored as they are, and `ce` correctly reports `"raw"` for them.

**An attachment GUID names exactly one attachment's content.** If your
application passes its own `guid` to `attach()` or `attach_file()`, it must be
a fresh one each time — reusing a GUID whose attachment is still waiting to be
uploaded raises `ValueError`. Omit `guid` to have the SDK generate one.

**The filename you pass to `attach_file()` travels with the attachment.** It
is sent as the package manifest's `orig_file_name`, alongside the GUID the
content is stored under, so the cloud can show the attachment under a name a
person recognizes:

```python
telemetry.attach_file("AppLog", "/var/log/myapp/app.log")   # arrives as "app.log"
telemetry.attach_file("AppLog", "tmp3x9f.tmp")              # arrives as "tmp3x9f.tmp"
```

Only the basename is sent, never the directory. A temporary file named after a
random token is a wasted field, so name the file for what it holds — or copy
it to a readable name before attaching.

`attach()` has no source file, since the SDK writes the payload into the store
itself, so the attachment's `name` is sent instead.

**A configured `InternetProxy` is the only route to the cloud.** An
application that names a proxy is taken to mean that telemetry goes through
that proxy or not at all. If the proxy is unreachable, flushes save to disk and
are retried later, exactly as they are when the network is down. Check that
`InternetProxy` is correct when telemetry stops arriving.

# Table of Contents

- [In-App Telemetry Python SDK](#in-app-telemetry-python-sdk)
  - [Version](#version)
  - [Configuration Notes](#configuration-notes)
- [Table of Contents](#table-of-contents)
- [Using In-App Telemetry](#using-in-app-telemetry)
  - [Installation](#installation)
    - [Pip](#pip)
    - [Poetry](#poetry)
  - [SDK Implementations](#sdk-implementations)
    - [Wrapper](#wrapper)
    - [IasPython](#iaspython)
  - [Enabling Logging](#enabling-logging)
  - [Running the Samples](#running-the-samples)
  - [Update Dependencies](#update-dependencies)
  - [Misc](#misc)

# Using In-App Telemetry

## Installation

The package is published as **`IasPython`**, and the implementation is currently at `1.0`. Thus you will be provided with a `.whl` file. Versions are four-part — `MAJOR.MINOR.BUILD.HOTFIX` — so the current package line is `IasPython` `1.0.x.0`, where the third component is the build that produced it and the fourth marks a hotfix on that build. When installing it will automatically find and install the latest package available for the version of python you are currently running. For python >= 3.11 it will download version `1.0.x.0`. An attempt to install a package version that is outside the range of your python version will throw an error and not download. Install as follows:

> **Note on the package name.** This SDK is published under a new distribution name, `IasPython`, rather than as a new version of `lanternrock`. The version line restarted at `1.0.0.0` (see below), which no version of `lanternrock` could express — pip would keep offering the older `lanternrock` `3.1.0` as the newer release. A new name sidesteps that entirely.
>
> The import name matches: `import iaspython` is how you use it. The two distributions no longer share an import path, so `IasPython` and the older `lanternrock` can be installed side by side without either shadowing the other.

> **Note on the version number.** The previous Lantern Rock SDK release was `3.1.0`, so this release is a lower number than the one before it. That is deliberate: the SDK has moved onto the SKR version line rather than continuing the Lantern Rock one, and it starts at `1.0.0.0` instead of carrying the old number forward — it cannot claim a version ahead of SKR itself. The first three components follow SemVer. See RFD-0194 for the full reasoning.
>
> Upgrading from a 3.x release is **not** a drop-in: the public Python API, the configuration semantics, the validation behavior and the supported Python runtime all changed. Read the release notes before upgrading.

### Pip

```
pip install <lr-wheel>

pip uninstall IasPython

```

### Poetry

```
poetry add <lr-wheel>
```

## SDK Implementations

### Wrapper

The older Lantern Rock Python SDK — the wrapper around the native C/C++ shared library — is not part of this package. It remains a separate product, installed as `lanternrock` and imported as `import lanternrock`, and is unaffected by anything documented here.

### IasPython

This SDK supports both asynchronous and synchronous styles, found under `iaspython.aio` and `iaspython.sync` respectively.

## Enabling Logging

This SDK supports both console and file logging. To enable logging, import and instantiate an instance of `TelemetryLogger` from either the async or sync code.

```py
from iaspython.aio import TelemetryLogger
# OR
from iaspython.sync import TelemetryLogger


lr_logger = TelemetryLogger()
```

Then use the following methods in order to configure your logs:

```py
lr_logger.set_console("INFO")
lr_logger.set_file("INFO", "/path/to/telemetry.log")
```

Valid logging levels can be found in Python's `logging` built-in.

## Running the Samples

You will find a handful of samples in the repository under `python/IasPython/examples`, and a sample for the older ctypes wrapper under `python/PythonWrapper`. They can be executed in an environment with IasPython installed with the following command:

```
python <lr-sample-file>
```
The `_cli` samples take the application name, telemetry id and output folder as arguments:

python sync_sample_cli.py appname 28b1df84-7568-4be8-afa7-3324434e1cea .

python async_sample_cli.py appname 28b1df84-7568-4be8-afa7-3324434e1cea .

The rest carry their configuration inline and take no arguments:

python sync_sample.py

python async_sample.py

python sync_sample_all.py

python async_sample_all.py

```

# Developing the In-App Telemetry SDK

## Dependencies

- [Python 3.11](https://www.python.org) or higher
- [Poetry](https://www.python-poetry.org)

## Building a Package

To build a a wheel and tar package, use the following command:

```
poetry build
```

The packages will be placed in the `dist` folder, for example, a wheel package: `dist\iaspython-1.0.0.0-py3-none-any.whl`. The filename carries the distribution name normalized to lowercase, which is how pip names wheels; `pip install IasPython` finds it either way. A locally built wheel carries the `version` in `pyproject.toml`; a published one carries `1.0.<build number>.0`, which the pipeline stamps over it.

## Virtual Environment

To set up the virtual environment use the following command:

```
poetry install
```

This will create a virtual environment if it doesn't already exist, and then install all the project dependencies.

This will fallback on your default Python version, depending on your operating system. If you wish to use a specific version of Python, you can use the following command:

```
poetry env use <target_version>
```

Poetry's docs contain further information on the use of this command.

## Unit Tests

To run the unit tests, use the following command:

```
poetry run pytest
```

## Documentation

The API reference is built with Sphinx from the docstrings, and lives in
`docs/`. Building it needs **Python 3.12 or newer** — Sphinx 9 does not support
3.11, which this SDK still targets, so the `docs` dependency group carries a
marker and resolves to nothing on 3.11.

```
poetry install --with docs
poetry run sphinx-build -W -b html docs docs/_build/html
```

Open `docs/_build/html/index.html`. `-W` turns warnings into errors, which is
how CI builds it; drop it to see the warnings without failing.

The reference pages are `autoclass` directives, not hand-written member lists,
so **adding, renaming or removing a method needs no edit here**. Only renaming
or removing a whole class or module breaks the build, and `docs/configuration.md`
pulls the "Configuration Notes" section out of this file by heading, so
renaming that heading breaks the build too. Both are deliberate.

### When pydoclint fails

`pydoclint` checks that each docstring's `Args:`, `Returns:` and `Raises:`
sections still agree with the function signature. It runs in pre-commit and in
CI. There is **no baseline file** — the package is clean, so anything it reports
is something this change introduced.

Renaming or deleting a parameter without updating its docstring entry looks
exactly like forgetting to write one, so an intentional API change will fail
this check. That is the point. Normally the fix is to edit the docstring:

```
cd python/IasPython
poetry run pydoclint iaspython
```

Two things that are *not* docstring bugs, and how they are handled:

- **A raise that happens in a helper.** `Telemetry.attach()` documents
  `TelemetryClosed` but raises it through `_check_initialized_or_raise()`, so
  pydoclint sees a `Raises:` section over a body with no `raise` and reports
  `DOC502`.
- **A bare `raise` in a cleanup handler.** `TelemetrySession.attach()`
  re-raises from `except BaseException` to release its claim, so pydoclint
  believes the body raises `BaseException` and reports `DOC503`.

Static analysis cannot see through either, and writing `Raises: BaseException`
to satisfy it would make the published docs wrong. Those cases carry a
suppression on the closing docstring line, with the reason in a comment beside
them:

```python
    Raises:
        TelemetryClosed: If Telemetry was closed.
    """  # noqa: DOC502
```

Add one only when the docstring is right and the tool is wrong. If you are
suppressing `DOC101` or `DOC103` — the args-versus-signature checks — stop and
fix the docstring instead; those are the ones that catch real drift, and the
only sanctioned exception is `TelemetryBase.__init__`, which hides three
internal keyword-only arguments from the published constructor on purpose.

To get a commit through mid-refactor: `SKIP=pydoclint git commit` skips just
this hook, `git commit --no-verify` skips all of them. CI still checks.

## Samples

To run the samples, use the following command:

```
poetry run python examples\async_sample_cli.py python-app 28b1df84-7568-4be8-afa7-3324434e1cea .
```


## Update Dependencies

To update dependencies open the pyproject.toml file and update the minimum required version number and use poetry to update.

- To see all the outdated packages: poetry show --outdated --top-level
- To see only the outdated packages in LR sdk: poetry show --outdated --top-level --only=main
- Open the pyproject.toml file
- Make your change - ex. 'aiohttp = "^3.9.2"' to 'aiohttp = "^3.9.4"'
- Open a cmd prompt where the pyproject.toml is located
- Run command 'poetry update'
- Save the now newly updated poetry.lock file

## Misc
- Find all python versions: winget search --id Python.Python
- Find specific python versions: winget search Python.Python.3.13 --versions
- Install a specific python version: winget install --id Python.Python.3.13 --exact --version 3.13.5 --interactive
