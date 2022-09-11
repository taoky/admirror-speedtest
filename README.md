# rsync-speedtest
A simple rsync speedtest program for multiple-IPs (ISP) environment, to optimize the speed of syncing from upstream.

## Args

```
$ ./rsync-speedtest --help
rsync-speedtest 
Test speed (bandwidth) of different bind IP to rsync upstream

USAGE:
    rsync-speedtest [OPTIONS] <UPSTREAM>

ARGS:
    <UPSTREAM>    Upstream path. Will be given to rsync

OPTIONS:
    -c, --config <CONFIG>      Config file (IP list) path. Default to ~/.rsync-speedtest
    -h, --help                 Print help information
        --log <LOG>            Rsync log file. Default to /dev/null
    -p, --pass <PASS>          Passes number. Default = 3 [default: 3]
    -t, --timeout <TIMEOUT>    Timeout (seconds). Default = 30 [default: 30]
        --tmp-dir <TMP_DIR>    Tmp file path. Default to env::temp_dir() (/tmp in Linux system)
```

## Config file format

```
114.5.1.4 example_ip_1
2001:19:19:8::10 example_ip_2
```
