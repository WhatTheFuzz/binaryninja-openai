nobrainer use:
```
cd ~/.binaryninja/plugins/
pip3 install openai
git clone https://github.com/pilvar222/binaryninja-openai
```
and set your api key in Edit->Preferences->Settings and search OpenAI, don't hesitate to also set a limit on your account so you don't get a aws-like surprise bill at the end of the month in case something fails lol 

Below is the original README

[![CodeQL](https://github.com/WhatTheFuzz/binaryninja-openai/actions/workflows/codeql.yml/badge.svg)](https://github.com/WhatTheFuzz/binaryninja-openai/actions/workflows/codeql.yml)

# BinaryNinja-OpenAI

Integrates OpenAI's GPT3 with Binary Ninja via a plugin and currently supports
two actions:

- Queries OpenAI to determine what a given function does (in Pseudo-C and HLIL).
  - The results are logged to Binary Ninja's log to assist with RE.
- Allows users to rename variables in HLIL using OpenAI.
  - Variable are renamed immediately and the decompiler is reloaded.

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

### What Does this Function Do?

After installation, you can right-click on any function in Binary Ninja and
select `Plugins > OpenAI > What Does this Function Do (HLIL/Pseudo-C)?`.
Alternatively, select a function in Binary Ninja (by clicking on any instruction
in the function) and use the menu bar options `Plugins > OpenAI > ...`. If your
cursor has anything else selected other than an instruction inside a function,
`OpenAI` will not appear as a selection inside the `Plugins` menu. This can
happen if you've selected data or instructions that Binary Ninja determined did
not belong inside of the function. Additionally, the HLIL options are context
sensitive; if you're looking at the decompiled results in LLIL, you will not see
the HLIL options; this is easily fixed by changing the user view to HLIL
(Pseudo-C should always be visible).

The output will appear in Binary Ninja's Log like so:

![The output of running the plugin.](https://github.com/WhatTheFuzz/binaryninja-openai/blob/main/resources/output.png?raw=true)

### Renaming Variables

I feel like half of reverse engineering is figuring out variable names (which
in-turn assist with program understanding). This plugin is an experimental look
to see if OpenAI can assist with that. Right click on an instruction where a
variable is initialized and select `OpenAI > Rename Variable (HLIL)`. Watch the
magic happen. Here's a quick before-and-after.

![Before renaming](https://github.com/WhatTheFuzz/binaryninja-openai/blob/main/resources/rename-before.png?raw=true)

![After renaming](https://github.com/WhatTheFuzz/binaryninja-openai/blob/main/resources/rename-after.png?raw=true)

Renaming variables only works on HLIL instructions that are initializations (ie.
`HighLevelILVarInit`). You might also want this to support assignments
(`HighLevelILAssign`), but I did not get great results with this. Most of the
responses were just `result`. If your experience is different, please submit a
pull request.

## OpenAI Model

By default, the plugin uses the `text-davinci-003` model, you can tweak this
inside Binary Ninja's preferences. You can access these settings as described in
the [API Key](#api-key) section. It uses the maximum available number of tokens
for each model, as described in [OpenAI's documentation][tokens].

## Known Issues

Please submit an issue if you find something that isn't working properly.

## License

This project is licensed under the [MIT license][license].

[default-plugin-dir]:https://docs.binary.ninja/guide/plugins.html
[token]:https://beta.openai.com/account/api-keys
[tokens]:https://beta.openai.com/docs/models/gpt-3
[entry]:./src/entry.py
[license]:./LICENSE
