# QBF Daemon

### Prerequisites

* Docker
* tmux (can be installed with brew or apt)

### A Note for Intel/AMD processors

Replace `linux-aarch64` with `linux-x86_64` in `client/Dockerfile`, `name_server/Dockerfile` and `resolver/Dockerfile`

### Running the Experiment

In terminal, `cd` into the project directory and then do:

  ```sh
  ./run_scenarios.bash
  ```

This will:

1. Build & create docker containers: `client`, `resolver`, `root nameserver`, `example nameserver`
2. Set network conditions: `50 Mbps bandwidth, 10 ms latency, 1232 Max UDP limit`
4. Sign zones with `FALCON-512`
5. Install QBF in `Parallel 1-RTT` mode on `resolver`, `root nameserver`, `example nameserver`
6. Perform 10 DNSSEC `TYPE A` queries using `client` and report the average resolution time

Note: Final DNS responses of `resolver` to `client` can be found in `build/dig_logs`

### Changing Parameters

This can be done by editing `run_scenarios.bash`

### Errors?

* Try re-running the experiment
* For slower machines, try increasing sleep times in `tmux-run-docker-part1.bash` and `tmux-run-docker-part2.bash`

### Printing logs in Containers

In `qbf-daemon/src/daemon.c`, set `bool debug = true;`.
Note that this will increase resolution times.

### A Note on SPHINCS+ in Parallel 1-RTT Mode

To get around a netfilter-queue issue with internal packets, we had to add a manual delay of 100 ms after sending the
original DNS query.
So to get the actual resolution time, subtract 100 ms from the reported time.



