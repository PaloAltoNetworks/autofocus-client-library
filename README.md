# AutoFocus Client Library

[![pipeline status](https://gitlab.gsrt.paloaltonetworks.local/gsrt-tools/autofocus-client-library/badges/master-python3/pipeline.svg)](https://gitlab.gsrt.paloaltonetworks.local/gsrt-tools/autofocus-client-library/commits/master-python3)
[![pipeline status](https://gitlab.gsrt.paloaltonetworks.local/gsrt-tools/autofocus-client-library/badges/master-python3/coverage.svg)](https://gitlab.gsrt.paloaltonetworks.local/gsrt-tools/autofocus-client-library/commits/master-python3)

## Install

```
sudo ./setup.py install
```

### Config File
Remember to create the file `~/.config/panw` and add the following section to it (note the lack of spaces and quotes)

```
[autofocus]
apikey=your-af-api-key-goes-here

# whether or not warning log level is displayed
# ignore_warnings = false

# disable ssl verification (not recommended unless debugging SSL/CA issues)
# ssl_verify = true

# uses default requests ca bundle by default, can override here by specifying path
# ssl_cert = <some_path>
```

If you write a script that isn't being run by your user, you can always manually set the API key via the following

```
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = "Your AF API Key Here"
```

## Examples

Should add some basic examples here, but most can be found in [examples](examples/)
