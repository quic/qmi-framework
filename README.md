# QMI - Qualcomm Messaging Interface

## QMI Big Picture
- **Inter-Processor Communication**: QMI is an IPC protocol used between software components hosted among a network of processors within a System-On-Chip (SoC).
- **Client-Server Model**: Based on a client-server communication model.
- **Asynchronous Interface**: Built using an asynchronous interface model.
- **Backward Compatibility**: Supports backward compatibility inherently.
- **Layered Implementation**: Follows a layered implementation.

## Client-Server Communication Model
- **Model**: QMI is based on a client-server communication model.
- **Hosting**: A client or a service can be hosted in any processor (nodes, subsystems).
- **Service Identification**: A service is identified by a client using a unique service name (`<service>:<instance>` combination). The `<service>` field is a 32-bit value assigned by the QMI CCB team, and the `<instance>` field is a 32-bit value assigned by the service owners.
- **Service Name**: Equivalent to a domain name on the internet.

## QMI Framework
- **Skeleton**: Enables sending and receiving QMI messages between multiple processors.
- **Mailman Role**: Acts as a mailman, not interpreting or tampering with the contents of the QMI messages.
- **APIs**: Provides APIs to implement clients and services.
- **Layering Model**: Strictly follows a layering model, with each layer performing well-defined operations and being decoupled from the implementation of its adjacent layer.

## Building
To build the QMI project, follow these steps:
1. Clone the QMI project.
2. Set up the proper toolchain for x86/ARM.
3. Navigate to the project directory:
    ```sh
    cd qmi_framework
    ```
4. Build the project:
    ```sh
    autoreconf --install
    ./configure
    make
    make install
    ```
    By default, ```./configure``` command will configure the project to install compiled libraries and
    binaires in system's ```/usr/lib``` and ```/usr/bin``` directories, respectively.
    To install libraries and binaries in custom directory, you can specify the directory by passing
    ```--prefix``` flag.
    For example: ```./configure --prefix=$(pwd)/install```

    Alternatively, you can also run the below script, passing the required compiler as an argument:
     ```sh
    ./build_script.sh
    ```
    For, ARM based targets:
    ```sh
    ./build_script.sh --host=aarch64-linux-gnu
    ```
    By default, it will compile for X86 target.

## Code Organization
- **qcci**: Provides functions that QMI clients can use to send and receive QMI messages.
- **qcsi**: Provides functions that QMI servers can use to send and receive QMI messages.
- **qencdec**: Provides functions to encode/decode QMI messages in TLV format.
- **common**: Provides common request and response messages that any QMI client can use.
- **tests**: Sample QMI client and service implementations.
- **include**: Contains headers to be included by QMI clients.

## License
qmi-framework is licensed under the BSD 3-clause "New" or "Revised" License.
