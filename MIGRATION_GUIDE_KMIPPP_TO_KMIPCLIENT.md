# Migration Guide: `kmippp::context` → `kmipclient`

This guide helps migrate code from the old `kmippp` wrapper to the new `kmipclient` library. The main challenge when using `kmippp::context` is its pointer-centric interface. **The new `kmipclient` now supports move-only semantics and shared handles to make this transition painless.**

---

## What's changed

| Aspect | Before (kmippp) | After (kmipclient) |
|--------|-----------------|-------------------|
| **Copy/Move semantics** | No copy, no move | Move-only (non-copyable) |
| **Ownership patterns** | Pointer-based or value-based | Value-based or `std::shared_ptr<Kmip>` |
| **Lifetime control** | Manual lifetime management | RAII with `close_on_destroy` flag |
| **Transport layer** | Opaque `kmippp::context` | Explicit `NetClient` interface + `KmipClient` |

---

## Pattern 1: Stack-allocated (simplest migration)

### Before (kmippp)
```cpp
#include "kmippp/kmipp.hpp"
using namespace kmippp;

context ctx = context::from_pem(host, port, cert, key, ca);
auto key_id = ctx.op_create_aes_key("mykey", "mygroup");
```

### After (kmipclient) - Option A: Reference-based
```cpp
#include "kmipclient/Kmip.hpp"
using namespace kmipclient;

Kmip kmip(host, port, cert, key, ca, timeout_ms);
auto key_id = kmip.client().op_create_aes_key("mykey", "mygroup");
```

**Pros:**
- Simple, familiar stack-based semantics
- Transport automatically closed on scope exit
- Zero-copy design for single-threaded use

**Cons:**
- Cannot share across scopes/threads without refactoring

---

## Pattern 2: Shared handle (pointer-centric migration)

This is the recommended pattern when migrating from `kmippp::context` where you were passing pointers or shared handles.

### Before (kmippp with shared context)
```cpp
auto ctx = std::make_shared<kmippp::context>(host, port, cert, key, ca);
std::vector<std::shared_ptr<kmippp::context>> contexts;
contexts.push_back(ctx);  // Share across threads
```

### After (kmipclient) - Option B: Shared handle
```cpp
#include "kmipclient/Kmip.hpp"
using namespace kmipclient;

auto kmip = Kmip::create_shared(host, port, cert, key, ca, timeout_ms);
std::vector<std::shared_ptr<Kmip>> handles;
handles.push_back(kmip);  // Share across threads
```

**Usage in threads:**
```cpp
std::thread t1([kmip] {
    auto key_id = kmip->client().op_create_aes_key("k1", "g1");
});
std::thread t2([kmip] {
    auto key_id = kmip->client().op_create_aes_key("k2", "g2");
});
t1.join();
t2.join();
// kmip transport closes when the last shared_ptr is destroyed
```

**Pros:**
- Drop-in replacement for `std::shared_ptr<kmippp::context>` patterns
- Transport lifetime tied to handle lifetime
- Thread-safe reference counting

**Cons:**
- Shared ownership overhead (slight performance cost)

---

## Pattern 3: Move semantics (new to kmipclient)

`KmipClient` is now move-only, enabling efficient transfer of ownership without copying.

### Using KmipClient directly with move
```cpp
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
using namespace kmipclient;

auto transport = std::make_shared<NetClientOpenSSL>(
    host, port, cert, key, ca, timeout_ms
);
transport->connect();

// Move the client into a unique_ptr or container
auto client = std::make_unique<KmipClient>(std::move(*transport), logger);
auto key_id = client->op_create_aes_key("mykey", "mygroup");
// client is destroyed when unique_ptr goes out of scope
```

**Pros:**
- Efficient single-ownership semantics
- No reference counting overhead
- Composes well with `std::unique_ptr`

---

## Pattern 4: Controlling transport lifetime with `close_on_destroy`

When you need to keep the transport alive after the client is destroyed:

### Stack-based with controlled lifetime
```cpp
// Default: close_on_destroy = true (transport closes on destruction)
Kmip kmip(host, port, cert, key, ca, timeout_ms);

// Keep transport alive: close_on_destroy = false
Kmip kmip(host, port, cert, key, ca, timeout_ms,
          kmipcore::KMIP_VERSION_1_4, nullptr, {}, false);
// Now the transport stays open after kmip is destroyed
```

### KmipClient with flag control
```cpp
auto transport = std::make_shared<NetClientOpenSSL>(...);

// Default: close_on_destroy = true
auto client = KmipClient::create_shared(transport);

// Or: don't close transport
auto client2 = KmipClient::create_shared(transport, logger, version, false);

// Query the setting
if (client2.close_on_destroy()) {
    std::cout << "Transport will close on destruction\n";
}
```

---

## Migration checklist

### Step 1: Replace includes
```cpp
// Before
#include "kmippp/kmipp.hpp"

// After
#include "kmipclient/Kmip.hpp"
```

### Step 2: Choose your ownership pattern
- **Single-threaded, stack-based?** → Use `Kmip` directly (Pattern 1)
- **Multi-threaded, shared handles?** → Use `Kmip::create_shared()` (Pattern 2)
- **Maximum efficiency, single ownership?** → Use `KmipClient` with move (Pattern 3)
- **Complex lifetime management?** → Use `close_on_destroy` flag (Pattern 4)

### Step 3: Update context creation
```cpp
// Before
context ctx = context::from_pem(...);

// After
Kmip kmip(...);
// or
auto kmip = Kmip::create_shared(...);
```

### Step 4: Update operation calls
```cpp
// Before
auto key_id = ctx.op_create_aes_key("name", "group");

// After (Pattern 1/2)
auto key_id = kmip.client().op_create_aes_key("name", "group");
// or
auto key_id = kmip->client().op_create_aes_key("name", "group");
```

### Step 5: Handle transport access (if needed)
```cpp
// Before
NetClient &transport = ctx.transport();  // (if exposed)

// After
NetClientOpenSSL &transport = kmip.transport();
// or const reference:
const auto &transport = kmip.client();  // for KMIP ops
```

---

## API equivalence

### Common operations

| kmippp::context | kmipclient::Kmip |
|---|---|
| `ctx.op_create_aes_key(name, group)` | `kmip.client().op_create_aes_key(name, group)` |
| `ctx.op_register_key(name, group, key)` | `kmip.client().op_register_key(name, group, key)` |
| `ctx.op_get_key(id)` | `kmip.client().op_get_key(id)` |
| `ctx.op_destroy(id)` | `kmip.client().op_destroy(id)` |
| `ctx.op_locate_by_name(name, type)` | `kmip.client().op_locate_by_name(name, type)` |

All operations throw `kmipcore::KmipException` on failure (same as kmippp).

---

## Error handling

Both libraries throw exceptions; error handling is nearly identical:

```cpp
// Before (kmippp)
try {
    auto key = ctx.op_get_key(id);
} catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
}

// After (kmipclient)
try {
    auto key = kmip.client().op_get_key(id);
} catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
}
```

For network errors, catch `KmipIOException`:
```cpp
try {
    auto key = kmip.client().op_get_key(id);
} catch (const KmipIOException &e) {
    std::cerr << "Network error: " << e.what() << '\n';
} catch (const kmipcore::KmipException &e) {
    std::cerr << "KMIP error: " << e.what() << '\n';
}
```

---

## Key differences to be aware of

1. **`Kmip` is an explicit facade, not just a context.**
   - It owns both the transport and client.
   - Access client via `.client()` (not implicit cast).

2. **Move semantics are now enabled.**
   - You can move clients around; can't copy them.
   - This enables efficient ownership transfer without shared_ptr overhead.

3. **Transport is explicitly typed as `NetClientOpenSSL`** when using `Kmip`.
   - The `kmipclient::KmipClient` class works with any `NetClient` implementation.
   - This allows dependency injection and custom transports.

4. **`close_on_destroy` flag is new.**
   - Default is `true` (transport closes when destroyed).
   - Set to `false` if you manage the transport separately.

---

## Example: Full multi-threaded migration

### Before (kmippp)
```cpp
auto ctx = std::make_shared<kmippp::context>(host, port, cert, key, ca);
std::vector<std::thread> workers;

for (int i = 0; i < 4; ++i) {
    workers.emplace_back([ctx, i] {
        auto key_id = ctx->op_create_aes_key(
            "key_" + std::to_string(i),
            "group"
        );
        std::cout << "Thread " << i << " → " << key_id << '\n';
    });
}

for (auto &t : workers) t.join();
```

### After (kmipclient)
```cpp
auto kmip = Kmip::create_shared(host, port, cert, key, ca, timeout_ms);
std::vector<std::thread> workers;

for (int i = 0; i < 4; ++i) {
    workers.emplace_back([kmip, i] {
        auto key_id = kmip->client().op_create_aes_key(
            "key_" + std::to_string(i),
            "group"
        );
        std::cout << "Thread " << i << " → " << key_id << '\n';
    });
}

for (auto &t : workers) t.join();
// Transport closes when the last kmip handle is destroyed
```

---

## Pattern 5: High-concurrency with connection pooling (NEW)

For scenarios with many concurrent threads or high throughput, use `KmipClientPool`
instead of a single shared client:

### Before (kmippp with manual pooling)

```cpp
// Manual pool management needed
std::vector<std::shared_ptr<kmippp::context>> pool;
std::mutex pool_mutex;

auto ctx = pool.empty() ?
    std::make_shared<kmippp::context>(host, port, cert, key, ca) :
    (pool.pop_back(), pool.back());  // simplified
```

### After (kmipclient with built-in pool)

```cpp
#include "kmipclient/KmipClientPool.hpp"
using namespace kmipclient;

KmipClientPool pool({
    .host = "kmip-server",
    .port = "5696",
    .client_cert = "/path/to/cert.pem",
    .client_key  = "/path/to/key.pem",
    .server_ca_cert = "/path/to/ca.pem",
    .timeout_ms = 5000,
    .max_connections = 16
});

// In each worker thread:
auto conn = pool.borrow();  // Waits if pool is exhausted
auto key_id = conn->op_create_aes_key("key_" + id, "group");
// conn returns to pool automatically (RAII)
```

**Pool features:**
- **Lazy creation:** connections established on-demand up to max_connections
- **Blocking `borrow()`:** waits indefinitely for availability
- **Timed `borrow(timeout)`:** deadline-based waiting
- **Non-blocking `try_borrow()`:** returns nullopt if exhausted
- **Health tracking:** mark connections as unhealthy to discard them
- **Thread-safe:** built-in mutex and condition variable
- **Diagnostics:** `available_count()`, `total_count()`, `max_connections()`

**Patterns:**

```cpp
// Blocking (recommended for steady workloads)
{
    auto conn = pool.borrow();
    conn->op_create_aes_key("name", "group");
}  // auto-returned

// Timed (with deadline)
{
    auto conn = pool.borrow(std::chrono::seconds(10));
    // throws KmipException if timeout
}

// Non-blocking (for optional operations)
if (auto conn_opt = pool.try_borrow()) {
    conn_opt->op_create_aes_key("name", "group");
} else {
    std::cerr << "Pool exhausted\n";
}

// Mark unhealthy on error (connection discarded on return)
try {
    auto conn = pool.borrow();
    conn->op_destroy(bad_id);
} catch (const std::exception &) {
    conn.markUnhealthy();  // Don't reuse this connection
    throw;
}
```

**Pool configuration validation:**
- `max_connections` must be > 0, throws `kmipcore::KmipException` if not
- Default max_connections: 16

---

## Next steps

- Review the [kmipclient README](kmipclient/README.md) for complete API documentation.
- Consult example programs in `kmipclient/examples/` for runnable samples.
- For connection pooling in multi-threaded scenarios, see `KmipClientPool`.
- Run integration tests: `cmake -DBUILD_TESTS=ON .. && ctest --test-dir . -R KmipClient`

