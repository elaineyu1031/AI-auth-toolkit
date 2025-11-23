# Anonymous Credential Service (ACS)

**Anonymous Credential Service (ACS)** is a high-availability, multi-tenant service designed to enable de-identified client authentication. By leveraging advanced cryptographic primitives, ACS ensures user privacy and security while maintaining computational efficiency.

[Read more about how Meta enables de-identified authentication at scale](https://engineering.fb.com/2022/03/30/security/de-identified-authentication-at-scale)

## Features

-   **Privacy-Preserving**: Authenticate clients without linking their identity to their activity.
-   **High Availability**: Designed for scale and reliability.
-   **Compute-Conscious**: Optimized for performance.
-   **Cryptographic Foundation**: Built on robust primitives including:
    -   **VOPRFs** (Verifiable Oblivious Pseudorandom Functions)
    -   **Blind Signatures**
    -   **Key Derivation Functions**

## Project Structure

This repository is organized into the following core components:

-   **`lib/`**: A portable and extensible C library implementing the core ACS logic. It relies solely on [libsodium](https://doc.libsodium.org/).
    -   See `SimpleAnonCredService` for usage examples.
-   **`demo/`**: A demonstration implementation of the service (Server + Client) in C++.
    -   Built using **Apache Thrift 0.16**.

## SimpleAnonCredService Workflow

The demonstration service implements the following protocol:

1.  **Public Key Retrieval (Optional)**:
    -   Client downloads the primary public key from the server to validate subsequent keys.
2.  **Attribute Key Retrieval**:
    -   Client requests a public key for specific "attributes" (e.g., use case name, date).
3.  **Token Blind Signing**:
    -   Client generates a token, blinds it, and sends it to the server.
    -   Server authenticates the request, signs the blinded token, and returns it.
    -   Client unblinds the signed token and verifies it using the public key and proof.
4.  **Token Redemption**:
    -   Client redeems the unblinded token.
    -   Server validates the secret and proceeds with the business logic upon success.

## Getting Started

### Prerequisites

-   [libsodium](https://doc.libsodium.org/)
-   [Apache Thrift 0.16](https://thrift.apache.org/)

### Build

To build the project, simply run `make` from the root of the repository:

```bash
make
```

### Docker Usage

For a quick start without installing local dependencies, use Docker:

1.  **Build the image**:
    ```bash
    docker build -t acs . --build-arg UBUNTU_VERSION=22.04
    ```

2.  **Run the server**:
    ```bash
    docker run --rm --init --name acs-container acs
    ```

3.  **Run the client** (in a separate terminal):
    ```bash
    docker exec acs-container client
    ```

## Author

**Elaine**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
