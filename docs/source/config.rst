Config file reference
=====================

Example config :
----------------

.. code-block:: TOML

    [API]
    url = "https://api.example.com" # Traefik API endpoint URL
    auth = true # Is the endpoint under authentication
    user = "" # If not under auth, keep both user and pass empty
    pass = ""

    [CF]
    api_token = "" # API token with ZONE:READ and DNS:WRITE permissions
    proxied = true
    TTL = 60

    [Records]
    IPv4 = "0.0.0.0" # Target IPv4
    # IPv6 = false # Uncomment this and comment (#) the other one to disable AAA records creation
    IPv6 = "" # Target IPv6

Reference :
-----------

API :
^^^^^

This part treats about the Traefik API part of the config file :

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

CF :
^^^^

This part treats about the Cloudflare part of the config file :

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
