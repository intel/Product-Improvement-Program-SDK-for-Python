# In-App Telemetry Python SDK

An In-App Telemetry SDK implemented entirely in Python. It exposes a pythonic
interface and relies on no C/C++ shared library.

# Using In-App Telemetry

## Installation

The package is published as `IasPython` (import name `iaspython`). Versions
are four-part (`MAJOR.MINOR.BUILD.HOTFIX`); pip installs the latest build for
your Python version (3.11+) unless you pin one.

```
pip install <iaspython-wheel>

pip uninstall IasPython
```

With Poetry:

```
poetry add <iaspython-wheel>
```

## Quick Usage

```python
from iaspython.sync import Telemetry

config = {
    "AppName": "python-app",
    "AppVersion": "1.0",
    "TelemetryId": "28b1df84-7568-4be8-afa7-3324434e1cea",
}

with Telemetry(config) as telemetry:
    telemetry.record_event("AppStarted")
    telemetry.flush()
```

The same API is available as coroutines under `iaspython.aio`.

## Configuration Notes

<details>
<summary>Click to expand configuration details</summary>

A few configuration options are worth knowing about.

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

`CollectorUrl` is the full base URL of the collector. The SDK appends only
`records` to it.

It is optional, and overrides the `_endpoint` the policy document supplies.
Leave it out to upload wherever the policy says, which is what the samples do
and what applications should do; set it only to point at a different
environment.

Note that leaving it out means the policy decides whether the SDK uploads at
all: a policy that supplies no `_endpoint` retires the agent, and recorded
data is then discarded rather than queued. `CollectorUrl` overrides that
decision, which is why the SDK's own tests set it.

It overrides the endpoint and nothing else. Flushing still needs a policy —
if none can be fetched or read from cache, the data is saved to disk and
retried later regardless of `CollectorUrl`. `_endpoint.backoff` also still
throttles how often the SDK uploads, so running a sample twice in quick
succession may not upload the second time.

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

**`InternetProxy` is optional, but setting it makes it mandatory.** Leave it
out and the SDK connects to the cloud directly. Set it and telemetry goes
through that proxy or not at all — there is no fallback to a direct
connection. If the proxy is unreachable, flushes save to disk and are retried
later, exactly as they are when the network is down. Check that
`InternetProxy` is correct when telemetry stops arriving.

</details>

# Developing the In-App Telemetry SDK

## Dependencies

- [Python 3.11](https://www.python.org) or higher
- [Poetry](https://www.python-poetry.org)

## Building a Package

To build a wheel and tar package, use the following command:

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

## Update Dependencies

To update dependencies open the pyproject.toml file and update the minimum required version number and use poetry to update.

- To see all the outdated packages: poetry show --outdated --top-level
- To see only the outdated packages in this SDK: poetry show --outdated --top-level --only=main
- Open the pyproject.toml file
- Make your change - ex. 'aiohttp = "^3.9.2"' to 'aiohttp = "^3.9.4"'
- Open a cmd prompt where the pyproject.toml is located
- Run command 'poetry update'
- Save the now newly updated poetry.lock file

## Misc
- Find all python versions: winget search --id Python.Python
- Find specific python versions: winget search Python.Python.3.13 --versions
- Install a specific python version: winget install --id Python.Python.3.13 --exact --version 3.13.5 --interactive
