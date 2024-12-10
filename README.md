![Finanziato dall'Unione europea | Ministero dell'Università e della Ricerca | Italia domani PNRR | iNEST ](assets/HEADER_INEST.png)

>Programma iNEST Codice ECS00000043 finanziato sui fondi PNRR MUR – M4C2” – Investimento 1.5. Avviso “Ecosistemi dell’Innovazione” 
>CUP progetto B33D24000100004

# Mosquitto OAuth Plugin

Custom plugin for Mosquitto that enables authentication and authorization using OAuth2 JWT tokens.

## Table of Contents

1. [About the Project](#about-the-project)
2. [Building](#building)
3. [Configuration](#configuration)
   1. [Mosquitto configuration](#mosquitto-configuration)
   2. [Keycloak configuration](#keycloak-configuration)
4. [License](#license)
5. [Author](#author)

## About the Project

The plugin authorizes subscriptions and publications for a mqtt broker based on the acl stated in `mqtt-acl` JWT claim.
The JWT Tokens are generated by an oauth authentication server (e.g. Keycloak) when a user logs in.
It is necessary, for the oauth server response, to return access tokens structured as follows:

```json
{
  "exp": 1720520595,
  // ...
  "mqtt_acl": {
    "subscribe": ["/test/+"],
    "publish": ["/test/AAA", "/test/BBB"],
    "superuser": false
  }
  // ...
}
```

- The `subscribe` field specifies the topics to which a client can subscribe.
- The `publish` field specifies the topics in which a client can publish.
- The `superuser` field indicates if a client has admin privileges.

### Connect to MQTT Broker

There are two ways to connect to the broker:

1. Specifying `username` and `password` of a user registered in the authentication service
   The plugin uses the username and password to authenticate the mqtt-client with oauth server. The client's permissions are retrieved by the returned access token.

2. Using the string `jwt` as the username and JWT token as the password.
   The plugin verifies the access token provided with the oauth server's public key and retrieves the client's permissions from it.

**[Back to top](#table-of-contents)**

## Building

To compile the project first install the dependencies and then run the following commands:

```bash
mkdir build && cd build
cmake ..
make
```

Then you can install the library in the `/usr/local/lib` path with the command:

```bash
sudo make install
```

### Build Dependencies

- Eclipse Mosquitto v2.0.18 (<https://github.com/eclipse/mosquitto>)
- Curl (<https://github.com/curl/curl>)
- LibJWT (<https://github.com/benmcollins/libjwt>)
- Jansson (<https://github.com/akheron/jansson>)

**[Back to top](#table-of-contents)**

## Configuration

### Mosquitto configuration

To enable the plugin the `plugin` configuration property in `mosquitto.conf` should point to the path of `mosquitto-oauth-plugin.so`.
See the example configuration file [mosquitto-example.conf](mosquitto-example.conf).

#### Available properties

Configuration properties are listed below:

| Property                            | Description                                               |
| :---------------------------------- | :-------------------------------------------------------- |
| `plugin_opt_oauth_jwt_key`          | PEM encoded key used for verification of the signature.   |
| `plugin_opt_oauth_jwt_validate_exp` | `true` if the expiry date of the JWT should be validated. |
| `plugin_opt_oauth_client_id`        | OAuth2 client id.                                         |
| `plugin_opt_oauth_client_secret`    | OAuth2 client secret.                                     |
| `plugin_opt_oauth_token_url`        | Token endpoint url of the OAuth2 server.                  |

### Keycloak configuration

An example of configuring Keycloak as authentication server is explained below.

#### 1. Add a group with attributes

We use attributes to handle the permissions of MQTT clients. These attributes can be assigned directly to the user or, more conveniently, managed within a group that can be assigned to the Keycloak user.
In the Keycloak Realm Console, click on "Groups", then on "Create Group" and give this group a unique name. Select the "Attributes" tab and add permissions by assigning key-value pairs to this group.
There are three different types of keys that can be repeated and control the group permissions.

| Attribute       | Type                  | Info                                                                                     |
| :-------------- | :-------------------- | :--------------------------------------------------------------------------------------- |
| mqtt_publ_topic | String                | Defines a topic (filter) in which the client is allowed to publish.                      |
| mqtt_subs_topic | String                | Defines a topic (filter) to which the client is allowed to subscribe.                    |
| mqtt_superuser  | Boolean (true, false) | Defines a superuser which has admin privileges on the broker. (Can be omitted if false). |

#### 2. Add Client Scope and Mappers

These attributes need to be mapped to the client. Select "Client Scopes" from the left menu and click "Create". Give it a name like `mqtt-acl`, use the openid-connect protocol and include it in the token scope. Click save to proceed.
You will be fowarded into the new client scope's edit view. Select the "Mappers" tab and click "Add mapper" > "By Configuration".
Select the mapper type "User Attribute" and add the attribute as specified in the table below. Make sure the "Add to access token" and "Add to userinfo" flags are set to true.
Add a mapper for each user attribute you just assigned to the group.

| Token Claim Name   | User Attribute  | Claim JSON Type | Multivalued | Aggregate attribute values |
| :----------------- | :-------------- | :-------------- | :---------- | :------------------------- |
| mqtt_acl.publish   | mqtt_publ_topic | String          | Yes         | Yes                        |
| mqtt_acl.subscribe | mqtt_subs_topic | String          | Yes         | Yes                        |
| mqtt_acl.superuser | mqtt_superuser  | Boolean         | No          | Yes                        |

#### 4. Add a Broker Client

To add an auth-client for the MQTT broker, click on "Clients", "Create", enter a client ID and click "Next".
Enable "Client authentication" and save the client. The "Credentials" tab will appear at the top and you can get the client secret there.

#### 3. Add the Scope to the Client

To make mappers accessible to the MQTT broker, you need to add the scope to the auth-client you use for the broker.
In order to do that, select "Clients" from the left menu, and select the auth-client from MQTT. Navigate to "Client Scopes" tab and click "Add client scope". Then select previously created `mqtt-acl` scope and add it as default.
You successfully set up your permission mappers. You can now add users to your groups or attributes directly to a user.

**[Back to top](#table-of-contents)**

## License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) file for details.

**[Back to top](#table-of-contents)**

## Author

- **[Cristiano Di Bari](https://github.com/cridiba)** - [cristiano.dibari@iotinga.it](mailto:cristiano.dibari@iotinga.it)

**[Back to top](#table-of-contents)**
