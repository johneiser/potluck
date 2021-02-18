
Potluck
=======

**Potluck** is a custom debugger combining dynamic instrumentation with symbolic execution. Built as a wrapper around `Frida <https://frida.re/docs/home>`_, Potluck can attach to and interact with arbitrary processes on any platform that Frida supports.

Use python3-pip to install:

.. code-block::

    sudo pip3 install git+https://github.com/johneiser/potluck.git


Once installed, the :code:`potluck` command becomes available. Simply launch a `frida-server <https://github.com/frida/frida/releases>`_ on the target and connect to it with the following command:

.. code-block::

    potluck -r 192.168.1.2:1337


Once connected, you will be presented with a command-line interface with varying functionality. For example, let's say we've connected to a Windows host at 192.168.1.2; we can list the notepad processes, attach to one of them, and dump the image base address.

.. code-block::

    [192.168.1.2:1337]> ps notepad*
    +-------+-------------+
    | pid   | name        |
    +-------+-------------+
    | 7928  | notepad.exe |
    | 8872  | notepad.exe |
    | 10848 | notepad.exe |
    +-------+-------------+
    [192.168.1.2:1337]> attach 8872
    [Session(pid=8872)]> modules notepad*
    -------------+----------------+--------+---------------------------------+
    | name        | base           | size   | path                            |
    +-------------+----------------+--------+---------------------------------+
    | notepad.exe | 0x7ff6ca880000 | 229376 | C:\Windows\system32\notepad.exe |
    +-------------+----------------+--------+---------------------------------+
    [Session(pid=8872)]> detach
    [192.168.1.2:1337]> exit


At any point, you can type :code:`help` to show the available commands or :code `help [command]` to show the usage details for a particular command.

.. code-block::

    [Session(pid=8872)]> help modules
    modules [name]
        list modules loaded in the process


Finally, the :code:`exit` command can be invoked at any point to cleanly detach from the process.

.. code-block::

    [Session(pid=8872)]> exit


While a lot of the functionality will be simply a wrapper around Frida's native functionality, Potluck is built to be extensible and include more sophisticated functionality like `angr <https://docs.angr.io>`_ integration.

---------

.. toctree::
    :maxdepth: 2
    :caption: Contents:


.. toctree::
    :maxdepth: 1

    changelog


* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
