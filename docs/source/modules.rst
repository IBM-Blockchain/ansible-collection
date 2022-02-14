..
.. SPDX-License-Identifier: Apache-2.0
..

Modules
=======

Modules can be used from the command line or in a playbook task. Ansible
executes each module, usually on the remote target node, and collects return
values.

While different modules perform different tasks, their interfaces and responses
follow similar patterns.


Invoking transactions
---------------------

Ansible modules should work on the principle that they are idempotent; the same playbook
can be executed more than once safetly. Submmiting a transactions to Fabric would break this concept.

The modules here are intended for administrative purposes; for this reason and to main the modules
as being idempotent there are no modules for general purpose transaction invoking.

Module reference
----------------

Reference material for each module contains documentation on what parameters
certain modules accept and what values they expect those parameters to be.


.. toctree::
   :maxdepth: 1
   :caption: Contents:
   :glob:

   modules/*


