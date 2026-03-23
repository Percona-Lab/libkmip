TODO
--
Done:

1. Re-write protocol serialization/deserialization completelly and remove the dependency on `kmip.c`
2. Multiple batch items requests and responses for cases like "register and activate", "revoke and destroy", 
"get key and attributes", etc.
3. Multiple attributes getting
4. Human-readable request and response logging

The list of things yet to be done

5. Asymmetric keys and certificates support
6. Version negotiation with the KMIP server (Default is 1.4)
7. Complete version 2.0 specification support in the scope of current functionality.
8. Additional security features like optional certificates verification, client authentication, etc.


