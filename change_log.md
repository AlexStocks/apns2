# apns2 #
---
*sync with sideshow/apns2 master branch*

## dev list ##
---

- 2017/03/29
    - 1 fix bug: add GetByCertEnv to get client's right host instead of DefaultHost(HostDevelopment)

- 2017/01/24
    - 1 add client.go:reconnect to reconnect APNs server when connection or http2 request timeout;
    - 2 sync with master;

- 2017/01/22
    - 1 add client_manager.go:(ClientManager)AddByCertFile to add Client by cert file;
    - 2 add client_manager.go:(ClientManager)GetByCertFile to get Client by cert file;
