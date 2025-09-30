TODO
--
The list of things yet to be done

1. Re-write protocol serialization/deserialization completelly and remove the dependency on `kmip.c`
2. Multiple batch items requests and responses for cases like "register and activate", "revoke and destroy", 
"get key and attributes", etc.
3. Multiple attributes getting
4. Asymmetric keys and certificates support
5. Version negotiation with the KMIP server (Default is 1.4)
6. Human-readable request and response logging

