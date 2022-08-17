Installation and use
====================

.. note::

    This guide is writen with Linux and MacOS in mind, but the script *should* work just fine on Windows

Preparation
-----------

To use |name|, you need to install **pipenv** so that it can manage the appropriate dependencies

To do so, you can follow any of the methods in :doc:`pipenv:install`, from the Pipenv documentation

If you already have a python install, you can use the following commands to prepare the setup :

.. code-block:: Bash

    pip install --user pipenv
    git clone https://github.com/signed-log/tcfig.git
    cd tcfig
    pipenv install

.. _config_quickstart:

Config file preparation
-----------------------

|name| uses a TOML_-formatted config file for which you can find the sample as :file:`config_sample.toml`

It is expected in the same directory as the script under the :file:`config.toml` name

Copy the sample config to :file:`config.toml` and then fill it using the follwing sections and the :ref:`cnf_reference`

.. code-block:: Bash

    cp config_sample.toml config.toml

.. _TOML: https://toml.io/en/

.. _traefik_quickstart:

Traefik configuration
---------------------

.. warning::

    Please make sure to take the appropriate security measures, like authentication, while enabling the endpoint.

    More info about the implications is available on the Traefik docs' security_ paragraph

By default, Traefik doesn't expose the api endpoint required to run |name|

To do so, you will need to follow the official guide_ from Traefik

.. note::
    |name| only supports either HTTP Basic Authentication or unauthenticated endpoints *not recommended*.

    It will not work with any authentication middleware that doesn't have a BasicAuth facility

.. _guide: https://doc.traefik.io/traefik/operations/api/
.. _security: https://doc.traefik.io/traefik/operations/api/#security

.. _cloudflare_quickstart:

Cloudflare configuration
------------------------

|name| needs a token with the appropriate permissions to access the DNS zones

Those permissions are :

Zone - Zone:Read and Zone - DNS:Write

.. note::
    Make sure to select the appropriate (or all) *Zone Resources* when creating the token

Everything about this process is explained in the official `Cloudflare Documentation`_.

.. warning::
    The token is only displayed once, make sure to put it in the :ref:`cnf_cloudflare` tag of the config file

.. _Cloudflare Documentation: https://developers.cloudflare.com/api/tokens/create

IP setting
----------

Set the IP addresses, IPv4 and *(optionnaly)* IPv6 for which the records are to point to

.. note::

    IPv6-only mode will come a bit later down the line


Run
---

After doing that you're ready to go, inside the script's directory, just run :

.. code-block:: Bash

    pipenv run tcfig.py run
