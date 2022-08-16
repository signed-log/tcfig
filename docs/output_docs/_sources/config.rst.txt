Config file reference
=====================

.. _cnf_example:

Example config
--------------

.. code-block:: TOML

    [TRAEFIK]
    url = "https://api.example.com" # Traefik API endpoint URL
    auth = true # Is the endpoint under authentication
    user = "" # If not under auth, keep both user and pass empty
    pass = ""

    [CLOUDFLARE]
    api_token = "" # API token with ZONE:READ and DNS:WRITE permissions
    proxied = true
    TTL = 60

    [IP]
    IPv4 = "" # Target IPv4
    # IPv6 = false # Uncomment this and comment (#) the other one to disable AAA records creation
    IPv6 = "" # Target IPv6

.. _cnf_reference:

Reference
---------

.. _cnf_traefik:

TRAEFIK
^^^^^^^

This part treats about the Traefik API part of the config file

+------+-------------------------------------------------+---------------+--------------------------------------------------------+
| Name | Usage                                           | Type expected | Example                                                |
+======+=================================================+===============+========================================================+
| url  | URL for the API dashboard of Traefik            | str           | "https://api.example.com"                              |
+------+-------------------------------------------------+---------------+--------------------------------------------------------+
| auth | Is the endpoint under HTML basic authentication | bool          | true                                                   |
+------+-------------------------------------------------+---------------+--------------------------------------------------------+
|                            The following two options are to be kept empty (i.e. "") if auth is false                            |
+------+-------------------------------------------------+---------------+--------------------------------------------------------+
| user | Username for Traefik API authentication         | str           | "admin"                                                |
+------+-------------------------------------------------+---------------+--------------------------------------------------------+
| pass | Password for Traefik API authentication         | str           | "$admin$$$3wds$" *(please use a more secure password)* |
+------+-------------------------------------------------+---------------+--------------------------------------------------------+

.. _cnf_cloudflare:

CLOUDFLARE
^^^^^^^^^^

This part treats about the Cloudflare part of the config file

+-----------+------------------------------------------------------------+---------------+-------------------------------------------+
| Name      | Usage                                                      | Type expected | Example                                   |
+===========+============================================================+===============+===========================================+
| api_token | Cloudflare token_ with zone:read and dns:write permissions | str           | "W8421DNpetaNTx0fQBP34PFppBXICNKAU9l3JJF" |
+-----------+------------------------------------------------------------+---------------+-------------------------------------------+
| proxied   | Wether to enable proxied switch on cloudflare              | bool          | true                                      |
+-----------+------------------------------------------------------------+---------------+-------------------------------------------+
| TTL       | DNS TTL (you can read more about this here_)               | int           | 60                                        |
+-----------+------------------------------------------------------------+---------------+-------------------------------------------+

.. _token: https://dash.cloudflare.com/profile/api-tokens
.. _here: https://www.varonis.com/blog/dns-ttl

.. _cnf_ip:

IP
^^

+------+---------------------------------------------+---------------+---------------+
| Name | Usage                                       | Type Expected | Example       |
+======+=============================================+===============+===============+
| ipv4 | IPv4 address to set the records to point to | str           | "0.0.0.0"     |
+------+---------------------------------------------+---------------+---------------+
| Set the following variable to false (without any quote) to disable ipv6 records    |
+------+---------------------------------------------+---------------+---------------+
| ipv6 | IPv6 address to set the records to point to | str           | "2001:db8::1" |
+------+---------------------------------------------+---------------+---------------+
