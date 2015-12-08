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
```

If you write a script that isn't being run by your user, you can always manually set the API key via the following

```
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = "Your AF API Key Here"
```

## Examples

Should add some basic examples here, but most can be found in [examples](examples/)
