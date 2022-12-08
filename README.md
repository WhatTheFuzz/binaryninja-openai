[![CodeQL](https://github.com/WhatTheFuzz/binaryninja-openai/actions/workflows/codeql.yml/badge.svg)](https://github.com/WhatTheFuzz/binaryninja-openai/actions/workflows/codeql.yml)

# BinaryNinja-OpenAI

Integrates OpenAI's GPT3 with Binary Ninja via a plugin. Creates a query asking
"What does this function do?" followed by the instructions in the High Level IL
function. Returns the response to the user in Binary Ninja's console.

## Installation

If you're installing this as a standalone plugin, you can place (or sym-link)
this in Binary Ninja's plugin path. Default paths are detailed on
[Vector 35's documentation][default-plugin-dir].

This plugin has been tested on macOS and Linux. It probably works on Windows;
please submit a pull request if you've tested it.

### Dependencies

- Python 3.10+
- `openai` installed with `pip3 install --user openai`

## API Key

This requires an [API token from OpenAI][token]. The plugin checks for the API
key in three ways (in this order).

First, it tries to read the key from Binary Ninja's preferences. You can
access the entry in Binary Ninja via `Edit > Preferences > Settings > OpenAI`.
Or, use the hotkey ⌘+, and search for `OpenAI`. You should see customizable
settings like so.

![Settings](https://github.com/WhatTheFuzz/binaryninja-openai/blob/main/resources/settings.png?raw=true)

Second, it checks the environment variable `OPENAI_API_KEY`, which you can set
inside of Binary Ninja's Python console like so:

```python
import os
os.environ["OPENAI_API_KEY"] = "INSERT KEY HERE"
```

Or you can write it to a file. The file is set in [entry.py][entry] and is a
parameter to the Agent class. By default it checks for the file
`~/.openai/api_key.txt`. You can add your API token like so:

```shell
mkdir ~/.openai
echo -n "INSERT KEY HERE" > ~/.openai/api_key.txt
```

Note that if you have all three set, the plugin defaults to one set in Binary
Ninja. If your API token is invalid, you'll receive the following error:

```python
openai.error.AuthenticationError: Incorrect API key provided: <BAD KEY HERE>.
You can find your API key at https://beta.openai.com.
```

## Usage

After installation, you can right-click on any function in Binary Ninja and
select `Plugins > OpenAI > What Does this Function Do (HLIL)?`. Alternatively,
select a function in Binary Ninja (by clicking on any instruction in the
function) and use the menu bar options
`Plugins > OpenAI > What Does this Function Do (HLIL)?`. If your cursor has
anything else selected other than an instruction inside a function, `OpenAI`
will not appear as a selection inside the `Plugins` menu. This can happen if
you've selected data or instructions that Binary Ninja determined did not belong
inside of the function.

The output will appear in Binary Ninja's Log like so:

![The output of running the plugin.](https://github.com/WhatTheFuzz/binaryninja-openai/blob/main/resources/output.png?raw=true)

## OpenAI Model

By default, the plugin uses the `text-davinci-003` model, you can tweak this
inside Binary Ninja's preferences. You can access these settings as described in
the [API Key](#api-key) section. It uses the maximum available number of tokens
for each model, as described in [OpenAI's documentation][tokens].

## Known Issues

The query does not use Python's [asyncio][asyncio] and thus blocks the main
thread. You may be unable to interact with the Binary Ninja UI while the query
is waiting to be resolved. In some cases, your operating system may detect that
Binary Ninja has stopped responding and ask you to Force Quit it. I have not
experience any egregiously long hangs, however. This is documented in issue
[#8][issue-8].

## License

This project is licensed under the [MIT license][license].

[default-plugin-dir]:https://docs.binary.ninja/guide/plugins.html
[token]:https://beta.openai.com/account/api-keys
[tokens]:https://beta.openai.com/docs/models/gpt-3
[entry]:./src/entry.py
[asyncio]:https://docs.python.org/3/library/asyncio.html
[issue-8]:https://github.com/WhatTheFuzz/binaryninja-openai/issues/8
[license]:./LICENSE
