# AutoFocus Client Library

## Install

```
sudo ./setup.py install
```

### Config File
Remember to create the file `~/.config/panw` and add the following section to it (note the lack of spaces and quotes)

```
[autofocus]
apikey=your-af-api-key-goes-here

# optional parameters below with their default values
# ignore_warnings = false  # whether or not warning log level is displayed
# ssl_verify = true  # disable ssl verification (not recommended unless debugging SSL/CA issues)
# ssl_cert = <some_path>  # uses default requests ca bundle by default, can override here by specifying path
```

If you write a script that isn't being run by your user, you can always manually set the API key via the following

```
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = "Your AF API Key Here"
```

## Examples

Should add some basic examples here, but most can be found in [examples](examples/)
