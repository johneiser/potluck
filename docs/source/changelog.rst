
Changelog
=========

0.3.5
^^^^^

January 27, 2021

- Moved image attribute to abstract agent interface


0.3.4
^^^^^

January 27, 2021

- Added lazy capturing of angr state
- Added attempt to guess image base path along with ability to manually specify


0.3.3
^^^^^

January 27, 2021

- Added reading and searching memory recursively


0.3.2
^^^^^

January 27, 2021

- Enriched imports/exports with module name
- Added parse_as and parse_line_as utilities
- Refactor agent, process, and thread interfaces with parsing utilities


0.3.1
^^^^^

January 25, 2021

- Changed interface registry from dict to list to preserve order
- Explicitly labeled printed tables to preserve order
- Added support for connecting to remote frida-server


0.3.0
^^^^^

January 24, 2021

- Added dumping memory maps
- Added angr concrete target
- Added capture of angr simulation state from concrete target


0.2.0
^^^^^

January 24, 2021

- Redesigned interface with adaptable prompt
  

0.1.0
^^^^^

January 19, 2021

- Moved angr to extra dependency [angr]
- Added pretty tables with extra dependency [pretty]
- Added run command argument for scripted execution
- Added CALL task to agent for calling exports while hooked
- Added search to both process and thread interfaces
- Added enabling hooks from process interface

0.0.1
^^^^^

January 18, 2021

- Initial upload
