The "kmipclient" library
--
KMIP client is the C++ library that allows simple access to the KMIP servers using the KMIP protocol.

The "kmipclient" library wraps up the low-level libkmip (kmip.h, kmip.c) into C++ code.
The purpose of such wrap-up is to:

## Design goals.

1. Provide easy to use and hard to misuse interface with forced error processing.
2. Hide low-level details.
3. Minimize manual memory management
4. Make the library easy to extend
5. Exclude mid-level (kmip_bio.c), use the low-level (kmip.c) only
6. Easy to replace network communication level
7. Testability

## External dependencies

No extra external dependencies should be used, except existing OpenSSL dependency.
KmipClient itself does not depend on any library except "kmip". The network communication level is injected
into KmipClient instance as implementation of the NetClient interface. The library has ready to use 
OpenSSL BIO based implementation called NetClientOpenSSL. User of the library can use any other library to
implement the communication level.

## High level design

The top interface wraps network communication level (based on OpenSSL) and the KMIP protocol encoding level. 
It is implemented as header-only class in the file “Kmip.hpp” and can be used similar to the old C++ wrapper 
(kmippp.h).  Actual high level interface consists of two headers: NetClient.hpp. and KmipClient.hpp.

The first interface is just a contract to wrap low-level network communications similar to well-known 
interfaces (socket, OpenSSL bio and others). It contains 4 methods only: connect(), close(), send() 
and receive(). This interface also has an implementation, declared  “NetClientOpenSSL.hpp”. 
It is based on OpenSSL BIO functions.

The second interface is actual KMIP protocol implementation. It requires a NetClient implementation 
as a dependency injection in the constructor. This interface is also similar to the existing C++ wrapper 
and can be used the similar whay when properly initialized with the  NetClient-derived instance.

The main difference to the “kmippp.h” is in-band error processing. It uses a template similar to
std::expected from the C++ 23. Though, project may use older C++ standard (C++ 20), so the interface 
includes a C++ 20 implementation, that wraps standard implementation or provides replacement if it is absent.

All KMIP request creation and encoding are encapsulated in the RequestFactory class. All operations are 
on stack and do not require memory management.

All KMIP responses processing are encapsulated in ResponseFactory class. It should be operated on stack 
to keep data in place. Copy and move operations are disabled.

By the protocol, parsed response contains one or more response batch items. To process these items, 
ResponseFactory class is used. It’s purpose is to extract values from the response batch item. V
alues are keys, secrets, attributes, etc. This class does not have a state and consists of static methods.

All operation in the low-level KMIP library are based on context structure KMIP. This structure is 
encapsulated in KmipCtx class along with operations on buffers, errors, etc. This class, once created, 
is passed by the reference to other classes of the “kmipclient” library. Copy and move operations are 
disabled for this class also. Usually, the instance of this class is created on stack in the high-level 
methods and does not require memory management.

The high-level interface usage example:

```C++
NetClientOpenSSL  net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
KmipClient client (net_client);

  const auto opt_key = client.op_get_key (argv[6]);
  if (opt_key.has_value ())
  {
    std::cout << "Key: 0x";
    auto k = opt_key.value ();
    print_hex (k.value());
  }
  else
  {
    std::cerr << "Can not get key with id:"<< argv[6] << " Cause: "<< opt_key.error().message << std::endl;
  };
```
As can be seen from the code above, the NetClientOpenSSL class instance is injected as dependency 
inversion into the KmipClient class instance. This approach allows to use any net connection with KmipClient. 
It is enough to derive the class from NetClient class and wrap 4 calls.

To understand, how to extend functionality, below is  example of request creation:

```C++
void
RequestFactory::create_get_rq (KmipCtx &ctx, const id_t &id)
{
  KmipRequest rq (ctx);
  TextString uuid = {};
  uuid.size = id.size ();
  uuid.value = const_cast<char *>(id.c_str ());

  GetRequestPayload grp {};
  grp.unique_identifier = &uuid;

  RequestBatchItem rbi {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_GET;
  rbi.request_payload = &grp;
  rq.set_batch_item (&rbi);
  rq.encode ();
}
```
In the example above we use low-level primitives from “kmip.h” to create the RequestBatchItem and 
then we add it to the internal member of “KmipRequest” class, which performs appropriate 
request encoding in to the KMIP context.

Below is an example of the response processing:

```C++
ve::expected<Key, Error>
ResponseResultFactory::get_key (ResponseBatchItem *rbi)
{
  auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
  switch (pld->object_type)
    {
      //name known key to KeyFactory types
    case KMIP_OBJTYPE_SYMMETRIC_KEY:
         KMIP_OBJTYPE_PUBLIC_KEY:
         KMIP_OBJTYPE_PRIVATE_KEY:
         KMIP_OBJTYPE_CERTIFICATE:
      {
        return KeyFactory::parse_response(pld);
      };
    default:
      return Error(-1,"Invalid response object type.");
    }
}

```
And here is an example of top-level function implementation

```C++
my::expected<Key, Error>
KmipClient::op_get_key (const id_t &id)
{
  KmipCtx ctx;
  RequestFactory request_factory(ctx);
  ResponseFactory rf(ctx);
  try
    {
      request_factory.create_get_rq (id);
      io->do_exchange (ctx);
      return rf.get_key(0);
    }
  catch (ErrorException &e)
    {
      return Error(e.code (), e.what ());
    }
}
```
As can be seen from the source code, each KMIP low-level entity is encapsulated in some C++ class,
therefore advanced C++ memory management is utilized. Also, the design is avoiding any kind 
of smart pointers (almost… sometimes we need it), utilizing on-stack variables. Raw pointers from 
the low-level code are  used rarely just to pass stack-based data for more detailed processing.

It is worth of mentioning, that KMIP protocol supports multiple request items ( batch items ) 
in one network request. For example, it might be combination of GET and GET_ATTRRIBUTE operations 
to have a key with set of it’s attributes. It is important to have key state attribute, 
because a key could be outdated, deactivated or marked as compromised.

The design of this library supports multiple batch items in requests and in responses.

## Usage

Please, seee usage examples in the "examples" directory

