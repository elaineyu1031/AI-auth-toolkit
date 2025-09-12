# API Reference

Complete API documentation for the AI Authentication Toolkit.

## Table of Contents

- [Curve API](#curve-api)
- [VOPRF API](#voprf-api)
- [KDF API](#kdf-api)
- [DLEQ Proof API](#dleq-proof-api)
- [Service API (Thrift)](#service-api-thrift)
- [Error Codes](#error-codes)
- [Type Definitions](#type-definitions)

## Curve API

### Overview

Abstract interface for elliptic curve operations.

### Data Structure

```c
typedef struct curve {
    size_t scalar_bytes;
    size_t element_bytes;
    
    void (*scalar_random)(unsigned char* out, size_t len);
    int (*scalar_add)(unsigned char* out, size_t out_len,
                     const unsigned char* a, size_t a_len,
                     const unsigned char* b, size_t b_len);
    int (*scalar_sub)(unsigned char* out, size_t out_len,
                     const unsigned char* a, size_t a_len,
                     const unsigned char* b, size_t b_len);
    int (*scalar_mul)(unsigned char* out, size_t out_len,
                     const unsigned char* a, size_t a_len,
                     const unsigned char* b, size_t b_len);
    int (*scalar_invert)(unsigned char* out, size_t out_len,
                        const unsigned char* a, size_t a_len);
    int (*element_add)(unsigned char* out, size_t out_len,
                      const unsigned char* a, size_t a_len,
                      const unsigned char* b, size_t b_len);
    int (*element_scalarmult)(unsigned char* out, size_t out_len,
                             const unsigned char* scalar, size_t scalar_len,
                             const unsigned char* element, size_t element_len);
    int (*element_scalarmult_base)(unsigned char* out, size_t out_len,
                                  const unsigned char* scalar, size_t scalar_len);
    int (*element_hash_to_group)(unsigned char* out, size_t out_len,
                                const unsigned char* input, size_t input_len);
} curve_t;
```

### Implementations

#### Ed25519

```c
void curve_ed25519_init(curve_t* curve);
```

**Description**: Initialize Ed25519 curve operations.

**Parameters**:
- `curve`: Pointer to curve structure to initialize

**Constants**:
- `scalar_bytes`: 32
- `element_bytes`: 32

**Example**:
```c
curve_t curve;
curve_ed25519_init(&curve);
```

#### Ristretto255

```c
void curve_ristretto_init(curve_t* curve);
```

**Description**: Initialize Ristretto255 curve operations.

**Parameters**:
- `curve`: Pointer to curve structure to initialize

**Constants**:
- `scalar_bytes`: 32
- `element_bytes`: 32

**Example**:
```c
curve_t curve;
curve_ristretto_init(&curve);
```

### Function Reference

#### scalar_random

```c
void scalar_random(unsigned char* out, size_t len);
```

**Description**: Generate a random scalar.

**Parameters**:
- `out`: Output buffer (must be `scalar_bytes` long)
- `len`: Length of output buffer

**Example**:
```c
unsigned char scalar[32];
curve.scalar_random(scalar, sizeof(scalar));
```

#### element_hash_to_group

```c
int element_hash_to_group(unsigned char* out, size_t out_len,
                         const unsigned char* input, size_t input_len);
```

**Description**: Hash arbitrary input to a curve element.

**Parameters**:
- `out`: Output buffer (must be `element_bytes` long)
- `out_len`: Length of output buffer
- `input`: Input data to hash
- `input_len`: Length of input data

**Returns**: 0 on success, negative on error

**Example**:
```c
unsigned char element[32];
const char* data = "Hello, World!";
int result = curve.element_hash_to_group(
    element, sizeof(element),
    (const unsigned char*)data, strlen(data));
```

---

## VOPRF API

### Overview

Verifiable Oblivious Pseudorandom Function implementations.

### Data Structure

```c
typedef struct voprf {
    size_t final_evaluation_bytes;
    curve_t* curve;
    
    enum voprf_error (*setup)(voprf_t* voprf,
                             unsigned char* sk, size_t sk_len,
                             unsigned char* pk, size_t pk_len);
    
    enum voprf_error (*blind)(voprf_t* voprf,
                             unsigned char* blinded_element, size_t blinded_element_len,
                             unsigned char* blinding_factor, size_t blinding_factor_len,
                             const unsigned char* input, size_t input_len);
    
    enum voprf_error (*evaluate)(voprf_t* voprf,
                                unsigned char* evaluated_element, size_t evaluated_element_len,
                                unsigned char* proof_c, size_t proof_c_len,
                                unsigned char* proof_s, size_t proof_s_len,
                                const unsigned char* sk, size_t sk_len,
                                const unsigned char* blinded_element, size_t blinded_element_len,
                                int flag_proof_generate);
    
    enum voprf_error (*verifiable_unblind)(voprf_t* voprf,
                                          unsigned char* unblinded_element, size_t unblinded_element_len,
                                          const unsigned char* proof_c, size_t proof_c_len,
                                          const unsigned char* proof_s, size_t proof_s_len,
                                          const unsigned char* blinding_factor, size_t blinding_factor_len,
                                          const unsigned char* evaluated_element, size_t evaluated_element_len,
                                          const unsigned char* blinded_element, size_t blinded_element_len,
                                          const unsigned char* pk, size_t pk_len,
                                          int flag_proof_verify);
    
    enum voprf_error (*client_finalize)(voprf_t* voprf,
                                       unsigned char* final_evaluation, size_t final_evaluation_len,
                                       const unsigned char* input, size_t input_len,
                                       const unsigned char* unblinded_element, size_t unblinded_element_len);
    
    enum voprf_error (*server_finalize)(voprf_t* voprf,
                                       unsigned char* final_evaluation, size_t final_evaluation_len,
                                       const unsigned char* input, size_t input_len,
                                       const unsigned char* sk, size_t sk_len);
} voprf_t;
```

### Implementations

#### Multiplicative Blinding (Recommended)

```c
void voprf_mul_twohashdh_init(voprf_t* voprf, curve_t* curve);
```

**Description**: Initialize VOPRF with multiplicative blinding.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `curve`: Pointer to initialized curve

**Constants**:
- `final_evaluation_bytes`: 64

**Example**:
```c
curve_t curve;
voprf_t voprf;
curve_ristretto_init(&curve);
voprf_mul_twohashdh_init(&voprf, &curve);
```

#### Exponential Blinding

```c
void voprf_exp_twohashdh_init(voprf_t* voprf, curve_t* curve);
```

**Description**: Initialize VOPRF with exponential blinding.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `curve`: Pointer to initialized curve

**Constants**:
- `final_evaluation_bytes`: 64

### Function Reference

#### setup

```c
enum voprf_error setup(voprf_t* voprf,
                      unsigned char* sk, size_t sk_len,
                      unsigned char* pk, size_t pk_len);
```

**Description**: Generate a server key pair. For demo purposes only; use KDF in production.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `sk`: Output buffer for secret key (must be `curve->scalar_bytes`)
- `sk_len`: Length of sk buffer
- `pk`: Output buffer for public key (must be `curve->element_bytes`)
- `pk_len`: Length of pk buffer

**Returns**: `VOPRF_SUCCESS` or error code

**Example**:
```c
unsigned char sk[32], pk[32];
enum voprf_error err = voprf.setup(&voprf, sk, sizeof(sk), pk, sizeof(pk));
if (err != VOPRF_SUCCESS) {
    // Handle error
}
```

#### blind

```c
enum voprf_error blind(voprf_t* voprf,
                      unsigned char* blinded_element, size_t blinded_element_len,
                      unsigned char* blinding_factor, size_t blinding_factor_len,
                      const unsigned char* input, size_t input_len);
```

**Description**: Client-side: Blind a token.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `blinded_element`: Output buffer for blinded element (must be `curve->element_bytes`)
- `blinded_element_len`: Length of blinded_element buffer
- `blinding_factor`: Output buffer for blinding factor (must be `curve->scalar_bytes`)
- `blinding_factor_len`: Length of blinding_factor buffer
- `input`: Token to blind
- `input_len`: Length of input token

**Returns**: `VOPRF_SUCCESS` or error code

**Important**: Store `blinding_factor` securely; needed for unblinding.

**Example**:
```c
unsigned char token[32];
randombytes_buf(token, sizeof(token));

unsigned char blinded[32], blinding[32];
enum voprf_error err = voprf.blind(&voprf,
    blinded, sizeof(blinded),
    blinding, sizeof(blinding),
    token, sizeof(token));
```

#### evaluate

```c
enum voprf_error evaluate(voprf_t* voprf,
                         unsigned char* evaluated_element, size_t evaluated_element_len,
                         unsigned char* proof_c, size_t proof_c_len,
                         unsigned char* proof_s, size_t proof_s_len,
                         const unsigned char* sk, size_t sk_len,
                         const unsigned char* blinded_element, size_t blinded_element_len,
                         int flag_proof_generate);
```

**Description**: Server-side: Evaluate (sign) a blinded element.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `evaluated_element`: Output buffer for evaluated element (must be `curve->element_bytes`)
- `evaluated_element_len`: Length of evaluated_element buffer
- `proof_c`: Output buffer for proof challenge (must be `curve->scalar_bytes`). Can be NULL if `flag_proof_generate` is 0.
- `proof_c_len`: Length of proof_c buffer
- `proof_s`: Output buffer for proof response (must be `curve->scalar_bytes`). Can be NULL if `flag_proof_generate` is 0.
- `proof_s_len`: Length of proof_s buffer
- `sk`: Server's secret key
- `sk_len`: Length of secret key
- `blinded_element`: Blinded element from client
- `blinded_element_len`: Length of blinded_element
- `flag_proof_generate`: 1 to generate proof, 0 to skip

**Returns**: `VOPRF_SUCCESS` or error code

**Example**:
```c
unsigned char evaluated[32], proof_c[32], proof_s[32];
enum voprf_error err = voprf.evaluate(&voprf,
    evaluated, sizeof(evaluated),
    proof_c, sizeof(proof_c),
    proof_s, sizeof(proof_s),
    sk, sizeof(sk),
    blinded_element, sizeof(blinded_element),
    1);  // Generate proof
```

#### verifiable_unblind

```c
enum voprf_error verifiable_unblind(voprf_t* voprf,
                                   unsigned char* unblinded_element, size_t unblinded_element_len,
                                   const unsigned char* proof_c, size_t proof_c_len,
                                   const unsigned char* proof_s, size_t proof_s_len,
                                   const unsigned char* blinding_factor, size_t blinding_factor_len,
                                   const unsigned char* evaluated_element, size_t evaluated_element_len,
                                   const unsigned char* blinded_element, size_t blinded_element_len,
                                   const unsigned char* pk, size_t pk_len,
                                   int flag_proof_verify);
```

**Description**: Client-side: Unblind evaluated element and optionally verify proof.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `unblinded_element`: Output buffer for unblinded element (must be `curve->element_bytes`)
- `unblinded_element_len`: Length of unblinded_element buffer
- `proof_c`: Proof challenge from server. Can be NULL if `flag_proof_verify` is 0.
- `proof_c_len`: Length of proof_c
- `proof_s`: Proof response from server. Can be NULL if `flag_proof_verify` is 0.
- `proof_s_len`: Length of proof_s
- `blinding_factor`: Blinding factor from blind()
- `blinding_factor_len`: Length of blinding_factor
- `evaluated_element`: Evaluated element from server
- `evaluated_element_len`: Length of evaluated_element
- `blinded_element`: Blinded element from blind()
- `blinded_element_len`: Length of blinded_element
- `pk`: Server's public key
- `pk_len`: Length of public key
- `flag_proof_verify`: 1 to verify proof, 0 to skip

**Returns**: `VOPRF_SUCCESS`, `VOPRF_PROOF_ERROR`, or other error code

**Example**:
```c
unsigned char unblinded[32];
enum voprf_error err = voprf.verifiable_unblind(&voprf,
    unblinded, sizeof(unblinded),
    proof_c, sizeof(proof_c),
    proof_s, sizeof(proof_s),
    blinding_factor, sizeof(blinding_factor),
    evaluated_element, sizeof(evaluated_element),
    blinded_element, sizeof(blinded_element),
    pk, sizeof(pk),
    1);  // Verify proof

if (err == VOPRF_PROOF_ERROR) {
    // Proof verification failed
}
```

#### client_finalize

```c
enum voprf_error client_finalize(voprf_t* voprf,
                                unsigned char* final_evaluation, size_t final_evaluation_len,
                                const unsigned char* input, size_t input_len,
                                const unsigned char* unblinded_element, size_t unblinded_element_len);
```

**Description**: Client-side: Generate shared secret for redemption.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `final_evaluation`: Output buffer for shared secret (must be `voprf->final_evaluation_bytes`)
- `final_evaluation_len`: Length of final_evaluation buffer
- `input`: Original token used in blind()
- `input_len`: Length of input
- `unblinded_element`: Unblinded element from verifiable_unblind()
- `unblinded_element_len`: Length of unblinded_element

**Returns**: `VOPRF_SUCCESS` or error code

**Example**:
```c
unsigned char shared_secret[64];
enum voprf_error err = voprf.client_finalize(&voprf,
    shared_secret, sizeof(shared_secret),
    token, sizeof(token),
    unblinded_element, sizeof(unblinded_element));
```

#### server_finalize

```c
enum voprf_error server_finalize(voprf_t* voprf,
                                unsigned char* final_evaluation, size_t final_evaluation_len,
                                const unsigned char* input, size_t input_len,
                                const unsigned char* sk, size_t sk_len);
```

**Description**: Server-side: Generate shared secret for validation.

**Parameters**:
- `voprf`: Pointer to VOPRF structure
- `final_evaluation`: Output buffer for shared secret (must be `voprf->final_evaluation_bytes`)
- `final_evaluation_len`: Length of final_evaluation buffer
- `input`: Token from client's redemption request
- `input_len`: Length of input
- `sk`: Server's secret key
- `sk_len`: Length of secret key

**Returns**: `VOPRF_SUCCESS` or error code

**Example**:
```c
unsigned char expected_secret[64];
enum voprf_error err = voprf.server_finalize(&voprf,
    expected_secret, sizeof(expected_secret),
    client_token, sizeof(client_token),
    sk, sizeof(sk));

// Compare with client-provided shared_secret
if (memcmp(expected_secret, client_secret, sizeof(expected_secret)) == 0) {
    // Valid redemption
}
```

---

## KDF API

### Overview

Key Derivation Functions for attribute-based key generation.

### Data Structure

```c
typedef struct kdf {
    curve_t* curve;
    
    int (*setup)(kdf_t* kdf,
                const unsigned char* master_secret, size_t master_secret_len);
    
    int (*derive_key_pair)(kdf_t* kdf,
                          unsigned char* sk, size_t sk_len,
                          unsigned char* pk, size_t pk_len,
                          unsigned char* pk_proof, size_t pk_proof_len,
                          const unsigned char** attributes, size_t num_attributes);
} kdf_t;
```

### Implementations

#### SDHI KDF (Recommended)

```c
void kdf_sdhi_init(kdf_t* kdf, curve_t* curve);
```

**Description**: Initialize SDHI (Secure Deterministic Hierarchical Instantiation) KDF.

**Example**:
```c
curve_t curve;
kdf_t kdf;
curve_ristretto_init(&curve);
kdf_sdhi_init(&kdf, &curve);
```

#### Naor-Reingold KDF

```c
void kdf_naor_reingold_init(kdf_t* kdf, curve_t* curve);
```

#### Default KDF

```c
void kdf_default_init(kdf_t* kdf, curve_t* curve);
```

### Function Reference

#### setup

```c
int setup(kdf_t* kdf,
         const unsigned char* master_secret, size_t master_secret_len);
```

**Description**: Initialize KDF with a master secret.

**Parameters**:
- `kdf`: Pointer to KDF structure
- `master_secret`: Master secret key (recommended: 32 bytes)
- `master_secret_len`: Length of master_secret

**Returns**: 0 on success, negative on error

**Example**:
```c
unsigned char master_secret[32];
randombytes_buf(master_secret, sizeof(master_secret));

int result = kdf.setup(&kdf, master_secret, sizeof(master_secret));
```

#### derive_key_pair

```c
int derive_key_pair(kdf_t* kdf,
                   unsigned char* sk, size_t sk_len,
                   unsigned char* pk, size_t pk_len,
                   unsigned char* pk_proof, size_t pk_proof_len,
                   const unsigned char** attributes, size_t num_attributes);
```

**Description**: Derive a key pair from attributes.

**Parameters**:
- `kdf`: Pointer to KDF structure
- `sk`: Output buffer for secret key (must be `curve->scalar_bytes`)
- `sk_len`: Length of sk buffer
- `pk`: Output buffer for public key (must be `curve->element_bytes`)
- `pk_len`: Length of pk buffer
- `pk_proof`: Output buffer for public key proof (must be 2 * `curve->scalar_bytes`)
- `pk_proof_len`: Length of pk_proof buffer
- `attributes`: Array of attribute strings
- `num_attributes`: Number of attributes

**Returns**: 0 on success, negative on error

**Example**:
```c
const char* attrs[] = {"app:mobile", "date:2024-01", "region:us-west"};
const unsigned char* attr_ptrs[] = {
    (const unsigned char*)attrs[0],
    (const unsigned char*)attrs[1],
    (const unsigned char*)attrs[2]
};

unsigned char sk[32], pk[32], proof[64];
int result = kdf.derive_key_pair(&kdf,
    sk, sizeof(sk),
    pk, sizeof(pk),
    proof, sizeof(proof),
    attr_ptrs, 3);
```

---

## DLEQ Proof API

### Overview

Discrete Logarithm Equality Proofs for verifiable key derivation and VOPRF operations.

### Functions

#### dleqproof_generate

```c
int dleqproof_generate(curve_t* curve,
                      unsigned char* proof_c, size_t proof_c_len,
                      unsigned char* proof_s, size_t proof_s_len,
                      const unsigned char* k, size_t k_len,
                      const unsigned char* A, size_t A_len,
                      const unsigned char* B, size_t B_len,
                      const unsigned char* C, size_t C_len,
                      const unsigned char* D, size_t D_len);
```

**Description**: Generate DLEQ proof that `log_A(B) = log_C(D)`.

**Parameters**:
- `curve`: Pointer to curve structure
- `proof_c`: Output buffer for challenge (must be `curve->scalar_bytes`)
- `proof_c_len`: Length of proof_c buffer
- `proof_s`: Output buffer for response (must be `curve->scalar_bytes`)
- `proof_s_len`: Length of proof_s buffer
- `k`: Secret scalar such that `B = A^k` and `D = C^k`
- `k_len`: Length of k
- `A`: First base element
- `A_len`: Length of A
- `B`: First exponentiated element (`B = A^k`)
- `B_len`: Length of B
- `C`: Second base element
- `C_len`: Length of C
- `D`: Second exponentiated element (`D = C^k`)
- `D_len`: Length of D

**Returns**: 0 on success, negative on error

#### dleqproof_verify

```c
int dleqproof_verify(curve_t* curve,
                    const unsigned char* proof_c, size_t proof_c_len,
                    const unsigned char* proof_s, size_t proof_s_len,
                    const unsigned char* A, size_t A_len,
                    const unsigned char* B, size_t B_len,
                    const unsigned char* C, size_t C_len,
                    const unsigned char* D, size_t D_len);
```

**Description**: Verify DLEQ proof.

**Parameters**:
- `curve`: Pointer to curve structure
- `proof_c`: Challenge from proof
- `proof_c_len`: Length of proof_c
- `proof_s`: Response from proof
- `proof_s_len`: Length of proof_s
- `A`, `B`, `C`, `D`: Same as in generate

**Returns**: 0 if proof valid, -1 if invalid

**Example**:
```c
// Generate proof
unsigned char proof_c[32], proof_s[32];
dleqproof_generate(&curve, 
    proof_c, sizeof(proof_c),
    proof_s, sizeof(proof_s),
    secret_key, sizeof(secret_key),
    generator, sizeof(generator),
    public_key, sizeof(public_key),
    H, sizeof(H),
    H_to_k, sizeof(H_to_k));

// Verify proof
int valid = dleqproof_verify(&curve,
    proof_c, sizeof(proof_c),
    proof_s, sizeof(proof_s),
    generator, sizeof(generator),
    public_key, sizeof(public_key),
    H, sizeof(H),
    H_to_k, sizeof(H_to_k));
    
if (valid == 0) {
    // Proof is valid
} else {
    // Proof is invalid
}
```

---

## Service API (Thrift)

### Overview

High-level service interface for anonymous credentials.

### Methods

#### getPrimaryPublicKey

```thrift
GetPrimaryPublicKeyResponse getPrimaryPublicKey();
```

**Description**: Retrieve the server's primary (master) public key.

**Returns**:
```thrift
struct GetPrimaryPublicKeyResponse {
    1: string primary_public_key;
}
```

**Example (C++)**:
```cpp
GetPrimaryPublicKeyResponse response;
client.getPrimaryPublicKey(response);
vector<unsigned char> primary_pk = decodeBase64(response.primary_public_key);
```

#### getPublicKeyAndProof

```thrift
GetPublicKeyResponse getPublicKeyAndProof(1: GetPublicKeyRequest request);
```

**Description**: Retrieve an attribute-specific public key with proof.

**Request**:
```thrift
struct GetPublicKeyRequest {
    1: list<string> attributes;
}
```

**Response**:
```thrift
struct GetPublicKeyResponse {
    1: string public_key;
    2: string public_key_proof;
}
```

**Example (C++)**:
```cpp
GetPublicKeyRequest request;
request.attributes = {"app:mobile", "date:2024-01"};

GetPublicKeyResponse response;
client.getPublicKeyAndProof(response, request);

vector<unsigned char> pk = decodeBase64(response.public_key);
vector<unsigned char> proof = decodeBase64(response.public_key_proof);
```

#### signCredential

```thrift
SignCredentialResponse signCredential(1: SignCredentialRequest request)
    throws (1: TokenEncodingException tokenEncodingException,
            2: VoprfErrorException voprfErrorException);
```

**Description**: Sign a blinded credential.

**Request**:
```thrift
struct SignCredentialRequest {
    1: string blinded_token;
    2: list<string> attributes;
}
```

**Response**:
```thrift
struct SignCredentialResponse {
    1: string evaluated_token;
    2: string proof_c;
    3: string proof_s;
}
```

**Exceptions**:
- `TokenEncodingException`: Invalid token encoding
- `VoprfErrorException`: VOPRF operation failed

**Example (C++)**:
```cpp
SignCredentialRequest request;
request.blinded_token = encodeBase64(blinded_element);
request.attributes = {"app:mobile", "date:2024-01"};

SignCredentialResponse response;
try {
    client.signCredential(response, request);
    
    vector<unsigned char> evaluated = decodeBase64(response.evaluated_token);
    vector<unsigned char> proof_c = decodeBase64(response.proof_c);
    vector<unsigned char> proof_s = decodeBase64(response.proof_s);
} catch (VoprfErrorException& e) {
    // Handle error
}
```

#### redeemCredential

```thrift
void redeemCredential(1: RedeemCredentialRequest request)
    throws (1: TokenEncodingException tokenEncodingException,
            2: VoprfErrorException voprfErrorException,
            3: CredentialMismatchException credentialMismatchException);
```

**Description**: Redeem a credential by validating the shared secret.

**Request**:
```thrift
struct RedeemCredentialRequest {
    1: string token;
    2: string shared_secret;
    3: list<string> attributes;
}
```

**Exceptions**:
- `TokenEncodingException`: Invalid token encoding
- `VoprfErrorException`: VOPRF operation failed
- `CredentialMismatchException`: Shared secret mismatch

**Example (C++)**:
```cpp
RedeemCredentialRequest request;
request.token = encodeBase64(original_token);
request.shared_secret = encodeBase64(shared_secret);
request.attributes = {"app:mobile", "date:2024-01"};

try {
    client.redeemCredential(request);
    // Success - credential is valid
} catch (CredentialMismatchException& e) {
    // Invalid credential
}
```

---

## Error Codes

### VOPRF Errors

```c
enum voprf_error {
    VOPRF_SUCCESS = 0,
    VOPRF_UNKNOWN_ERROR = -1,
    VOPRF_BUFFER_LENGTH_ERROR = 1,
    VOPRF_CURVE_OPERATION_ERROR = 2,
    VOPRF_HASH_OPERATION_ERROR = 3,
    VOPRF_PROOF_ERROR = 4,
};
```

| Code | Name | Description |
|------|------|-------------|
| 0 | `VOPRF_SUCCESS` | Operation succeeded |
| -1 | `VOPRF_UNKNOWN_ERROR` | Unknown error occurred |
| 1 | `VOPRF_BUFFER_LENGTH_ERROR` | Buffer size incorrect |
| 2 | `VOPRF_CURVE_OPERATION_ERROR` | Elliptic curve operation failed |
| 3 | `VOPRF_HASH_OPERATION_ERROR` | Hash operation failed |
| 4 | `VOPRF_PROOF_ERROR` | Proof verification failed |

---

## Type Definitions

### Size Constants

**Ristretto255 / Ed25519**:
- Scalar size: 32 bytes
- Element size: 32 bytes
- Public key size: 32 bytes
- Secret key size: 32 bytes
- DLEQ proof size: 64 bytes (c + s)
- Final evaluation size: 64 bytes

### Encoding

All binary data in Thrift API is Base64-encoded.

**Encoding Example (C++)**:
```cpp
string encodeBase64(const vector<unsigned char>& data) {
    // Use your preferred Base64 library
    return base64_encode(data.data(), data.size());
}

vector<unsigned char> decodeBase64(const string& str) {
    return base64_decode(str);
}
```

---

## Complete Usage Example

```c
#include "src/crypto/curve/curve_ristretto.h"
#include "src/crypto/voprf/voprf_mul_twohashdh.h"
#include "src/crypto/kdf/kdf_sdhi.h"

int main() {
    // Initialize
    curve_t curve;
    curve_ristretto_init(&curve);
    
    voprf_t voprf;
    voprf_mul_twohashdh_init(&voprf, &curve);
    
    kdf_t kdf;
    kdf_sdhi_init(&kdf, &curve);
    
    // Server: Setup
    unsigned char master_secret[32];
    randombytes_buf(master_secret, sizeof(master_secret));
    kdf.setup(&kdf, master_secret, sizeof(master_secret));
    
    // Derive key for attributes
    const char* attrs[] = {"app:test"};
    const unsigned char* attr_ptrs[] = {(const unsigned char*)attrs[0]};
    unsigned char sk[32], pk[32], pk_proof[64];
    kdf.derive_key_pair(&kdf, sk, 32, pk, 32, pk_proof, 64, attr_ptrs, 1);
    
    // Client: Blind token
    unsigned char token[32];
    randombytes_buf(token, sizeof(token));
    
    unsigned char blinded[32], blinding[32];
    voprf.blind(&voprf, blinded, 32, blinding, 32, token, 32);
    
    // Server: Evaluate
    unsigned char evaluated[32], proof_c[32], proof_s[32];
    voprf.evaluate(&voprf, evaluated, 32, proof_c, 32, proof_s, 32,
                   sk, 32, blinded, 32, 1);
    
    // Client: Unblind and verify
    unsigned char unblinded[32];
    enum voprf_error err = voprf.verifiable_unblind(&voprf,
        unblinded, 32, proof_c, 32, proof_s, 32,
        blinding, 32, evaluated, 32, blinded, 32, pk, 32, 1);
    
    if (err != VOPRF_SUCCESS) {
        printf("Verification failed!\n");
        return 1;
    }
    
    // Client: Finalize
    unsigned char client_secret[64];
    voprf.client_finalize(&voprf, client_secret, 64, token, 32, unblinded, 32);
    
    // Server: Validate
    unsigned char server_secret[64];
    voprf.server_finalize(&voprf, server_secret, 64, token, 32, sk, 32);
    
    if (memcmp(client_secret, server_secret, 64) == 0) {
        printf("Success! Secrets match.\n");
    } else {
        printf("Failed! Secrets don't match.\n");
    }
    
    return 0;
}
```

