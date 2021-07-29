### Description ###
TLS Monitor is BPF application for monitoring TLS (v1.0, v1.1, v1.2) connection for specific process.
Internally, it adds hook to read()/write() syscalls and does parsing of payload.
If TLS pattern is found, it emits BPF event.

### Deependencies ###
* clang 12
* llvm-dev, clang-dev packages (bcc requirements)
* cmake

Note : clang 11 has an issue with building bcc.


### HOWTO ###
Run application as :
```
$ sudo tlsmon <pid>
```

where pid is a process pid you want to monitor.
Example:
```
$ sudo ./tlsmon 1044185
attached to pid [1044185]
TLS peer : 0.0.0.0:43950

```