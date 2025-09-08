## Objective

- The initial objective of this ambitious project is to
  1. Write an eBPF program which can be modifed at our will that can filter/trace http traffic on the port that we define.
  2. Extract the important information from the http packet like source and destination ports, data in the packet and more.
  3. Use BPF print to output the realtime logs to the trace_pipe

- The eBPF program in this repository, currently does exactly this, it is very simple to run and load this file.

**Before loading the file, let us first install all of the dependencies so that there won't be an issue while compiling and loading the program**

1. Update the system files.

```bash
sudo apt update
sudo apt upgrade
```

2. Run these commands in order

```bash
sudo apt install build-essential //having essential files
sudo apt install linux-headers-$(uname -r) //installing the required headers.
sudo apt install clang llvm //installing clang and llvm
sudo apt install libbpf-dev
sudo apt install libz-dev libelf-dev libcap-dev binutils-dev
sudo apt install bpftool
sudo apt install bpfcc-tools libbpfcc-dev
sudo apt-get install bcc-tools libbcc-examples
sudo apt install bpftrace
mount | grep /sys/fs/bpf  //this should already be mounted, but if not then mount it. 
```
3. Create a venv for python to install FastAPI. 

IMPORTANT!!

- Along with installing all of the essential files and tools, we also have to create a symlink
to get all of the files from `include/x86_84` to `include/asm` so that there won't be any issues during the compilation.

```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

### Running and Loading the file

- One you made sure that, everything above is properly handled, we can start compiling the code and loading it to our prefered network interface.

1. Compiling the program

```bash
clang -O2 -g -target bpf -c http_packet_sniffer.c -o http_packet_sniffer.o
```

2. My Objective required me to attach the program to Traffic Control( can also be done at `XDP`)

- create a clsact qdisc on the required interface(loopback, eth0 ...etc)

  ```bash
    sudo tc qdisc add dev lo //any other interface that you want to attach to clsact
- attach the program using the command
  ``` bash
  tc filder add dev <tailnet0>/<lo> ingress/egress bpf obj http_packet_sniffer.o sec tc

3. Use bpftool to verify the loaded program

  ```bash
  sudo bpftool net
```

### Viewing the result
1. Here, to simulate the incoming http traffic, I created a simple fastapi application which has an endpoint `localhost:port/{id}` (run `fastapi run main.py`)

2. When the FastAPI application is running, and whenever we use a curl to POST some data to that endpoint, we are basically sending data over the `http` protocol.

3. Finally, to view the output in realtime, go to the location where the log buffer is update

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Next Step?
1. With this setup, I was able to extact the data that is being sent over the http protocol to the system, and am very well capable of filtering the packets at the NIC itself. 

2. For implementation of packet filtering, I am planning to Use Machine Learning by Training a Model on any of the CIC DDoS/HTTP dataset and making it run in the user-space. 

3. Whenever the eBPF program detects any incoming HTTP packets, it passes the data inside it to the userspace for validation with the ML model, and according to the prediction, the program is able DROP or PASS the datapacket to the userspace for applications.

### Further implementations
1. Expand this to HTTPS traffic for secure processing of data.
2. Add more determination factors like IP reputation, Behavioral Correlation, signatures for Detection and filtering of malicious Data packets sent to the device.
3. Make the implementation easier by using CO-RE principles for easy deployments
4. Make it, usable for distributed systems which run containerised and microserviced-applications.
