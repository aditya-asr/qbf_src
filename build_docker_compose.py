#! /bin/python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--bypass", action="store_true")
parser.add_argument("--maxudp", required=True)
parser.add_argument("--alg")
parser.add_argument("--mode")
args = parser.parse_args()
BYPASS = args.bypass
maxudp = int(args.maxudp)
algorithm = str(args.alg)
mode = str(args.mode)

print("Using algorithm: {} and maxudp: {} and mode: {}".format(algorithm, str(maxudp), str(mode)))

if (maxudp != 1232):
    print("maxudp is wrong. maxudp: " + str(maxudp))
    exit()

import os

# Check if we are working with clean build dir or not

if os.path.isdir("build/"):
    print("Looks like you have a previous build setup. Do you want to replace it with this one?")
    print("This WILL destroy your previous network")
    print("Please enter:")
    print("     \"Y\" for yes")
    print("     \"N\" for no")
    user_input = input()
    while user_input != "Y" and user_input != "N":
        print("Invalid input, please enter:")
        print("     \"Y\" for yes")
        print("     \"N\" for no")
        user_input = input()

    if user_input == "N":
        print("Canceling build.")
        exit()

    os.system("rm -rf build/")

os.mkdir("build/")

# os.system("docker compose down --volumes 2> /dev/null")
# os.system("docker volume rm build_dsset-volume 2> /dev/null")
# os.system("docker network rm build_external_net build_internal_net 2> /dev/null")

# read in json files to build doocker-compose file, and move/modify Dockerfiles as needed
# Currently there is 0 sanity checking for if zone files make sense, would be nice to add later

# Parsing order: networks.json, clients.json, hosts.json, resolvers.json, name_servers.json

import json

docker_compose_file = open("build/docker-compose.yml", "w")
docker_compose_file.write("version: \"3.9\"\n\n")

network_data = None
with open("networks.json", "r") as f:
    network_data = json.load(f)
    network_data = network_data["networks"]

if network_data == None:
    raise RuntimeError("Unable to load networks.json")

docker_compose_file.write("networks:\n")

for network in network_data:
    docker_compose_file.write("    " + network["name"] + ":\n")
    docker_compose_file.write("        ipam:\n")
    docker_compose_file.write("            driver: default\n")
    docker_compose_file.write("            config:\n")
    docker_compose_file.write("                - subnet: " + network["subnet"] + "\n")
    docker_compose_file.write("                  gateway: " + network["gateway"] + "\n")
    docker_compose_file.write("        driver_opts:\n")
    docker_compose_file.write("            com.docker.network.driver.mtu: 65535\n")

client_data = None
with open("clients.json", "r") as f:
    client_data = json.load(f)
    client_data = client_data["clients"]

if client_data == None:
    raise RuntimeError("Unable to load clients.json")

docker_compose_file.write("services:\n")

for client in client_data:
    docker_compose_file.write("    " + client["name"].replace(".", "_") + ":\n")
    os.mkdir("build/" + client["name"])
    os.system("cp client/Dockerfile build/" + client["name"] + "/Dockerfile")
    docker_compose_file.write("        build: " + client["name"] + "/\n")
    docker_compose_file.write("        stdin_open: true\n")
    docker_compose_file.write("        privileged: true\n")
    docker_compose_file.write("        tty: true\n")
    docker_compose_file.write("        dns: " + client["dns_ip"] + "\n")
    docker_compose_file.write("        cap_add:\n")
    docker_compose_file.write("           - NET_ADMIN\n")
    docker_compose_file.write("        entrypoint: /bin/bash" + "\n")
    docker_compose_file.write("        networks:" + "\n")
    for network in client["networks"]:
        docker_compose_file.write("            " + network["network_name"] + ":" + "\n")
        docker_compose_file.write("                ipv4_address: " + network["ip_address"] + "\n")

resolver_data = None
with open("resolvers.json", "r") as f:
    resolver_data = json.load(f)
    resolver_data = resolver_data["resolvers"]

if resolver_data == None:
    raise RuntimeError("Unable to load resolvers.json")

for resolver in resolver_data:
    if resolver["name"][len(resolver["name"]) - 1] == ".":
        name = resolver["name"][:-1]
    else:
        name = resolver["name"]
    docker_compose_file.write("    " + name.replace(".", "_") + ":\n")
    os.mkdir("build/" + resolver["name"])
    os.mkdir("build/" + resolver["name"] + "/qbf")
    os.system("cp resolver/Dockerfile build/" + resolver["name"] + "/Dockerfile")
    os.system("cp resolver/*.bash build/" + resolver["name"])
    os.system("cp resolver/named.conf build/" + resolver["name"])
    os.system("cp resolver/root.hints build/" + resolver["name"])
    os.system("cp -r qbf-daemon/* build/" + resolver["name"] + "/qbf")
    with open("build/" + resolver["name"] + "/Dockerfile", "a") as f:
        if BYPASS:
            f.write(
                "CMD /setup_files/install_trust_anchor.bash && rm -rf /dsset/* && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && ./qbf/daemon ${LISTENIP} --bypass & named -g -d 3\n")
        else:
            f.write(
                "CMD /setup_files/install_trust_anchor.bash && rm -rf /dsset/* && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && ./qbf/daemon ${LISTENIP} --maxudp " + str(
                    maxudp) + " --algorithm " + algorithm + " --mode " + mode + " --is_resolver & named -g -d 3\n")

    docker_compose_file.write("        build:\n")
    docker_compose_file.write("            context: " + resolver["name"] + "/\n")
    docker_compose_file.write("            args:\n")
    docker_compose_file.write("                LISTENIP: " + resolver["networks"][0]["ip_address"] + "\n")
    docker_compose_file.write("        stdin_open: true\n")
    docker_compose_file.write("        privileged: true\n")
    docker_compose_file.write("        tty: true\n")
    docker_compose_file.write("        networks:\n")
    for network in resolver["networks"]:
        docker_compose_file.write("            " + network["network_name"] + ":\n")
        docker_compose_file.write("                ipv4_address: " + network["ip_address"] + "\n")
    docker_compose_file.write("        volumes:\n")
    docker_compose_file.write("            - dsset-volume:/dsset\n")
    docker_compose_file.write("        cap_add:\n")
    docker_compose_file.write("           - NET_ADMIN\n")

ns_data = None
with open("name_servers.json", "r") as f:
    ns_data = json.load(f)
    ns_data = ns_data["name_servers"]

if ns_data == None:
    raise RuntimeError("Unable to load name_servers.json")

for name_server in ns_data:
    if name_server["name"][len(name_server["name"]) - 1] == ".":
        name = name_server["name"][:-1]
    else:
        name = name_server["name"]
    docker_compose_file.write("    " + name.replace(".", "_") + ":\n")
    os.mkdir("build/" + name_server["name"])
    os.mkdir("build/" + name_server["name"] + "/qbf")
    os.system("cp name_server/Dockerfile build/" + name_server["name"] + "/Dockerfile")
    os.system("cp name_server/named.conf build/" + name_server["name"])
    os.system("cp name_server/*.bash build/" + name_server["name"])
    os.system("cp name_server/" + name_server["file"] + " build/" + name_server["name"])
    os.system("cp -r qbf-daemon/* build/" + name_server["name"] + "/qbf")
    # TODO set up reverse zones... should abstract this.
    named_conf_file = open("build/" + name_server["name"] + "/named.conf", "a")
    named_conf_file.write("\nzone \"" + name_server["zone"] + "\" IN {\n")
    named_conf_file.write("    type master;\n")
    named_conf_file.write("    file \"/usr/local/etc/bind/zones/" + name_server["file"] + ".signed\";\n")
    named_conf_file.write("};\n")
    named_conf_file.close()
    if name_server["zone"] == ".":
        zone = "root"
    else:
        zone = name_server["zone"][:-1]
    docker_file = open("build/" + name_server["name"] + "/Dockerfile", "a")
    docker_file.write("COPY db." + zone + " /usr/local/etc/bind/zones\n")
    if zone == "root":
        zone = "."
    if algorithm == "RSASHA256":
        docker_file.write(
            "RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a " + algorithm + " -b 2048 -n ZONE " + zone + "\n")
        docker_file.write(
            "RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a " + algorithm + " -b 2048 -n ZONE -f KSK " + zone + "\n")
    else:
        docker_file.write(
            "RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a " + algorithm + " -n ZONE " + zone + "\n")
        docker_file.write(
            "RUN cd /usr/local/etc/bind/zones && dnssec-keygen -a " + algorithm + " -n ZONE -f KSK " + zone + "\n")
    docker_file.write("RUN cd /usr/local/etc/bind/ && rndc-confgen -a > rndc.key\n")
    if name_server["leaf"] == "true":
        if zone == ".":
            zone = "root"
            out = "."
        else:
            zone = name_server["zone"][:-1]
            out = zone
        docker_file.write("ARG SIGN=unknown\n")
        docker_file.write("RUN echo $SIGN\n")
        docker_file.write(
            "RUN cd /usr/local/etc/bind/zones && dnssec-signzone -o " + out + " -N INCREMENT -t -S -K /usr/local/etc/bind/zones db." + zone + "\n")
        if BYPASS:
            docker_file.write("CMD /setup_files/move_ds.bash " + name_server[
                "zone"] + " && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && cd / && ./qbf/daemon ${LISTENIP} --bypass & named -d 3 && /bin/bash\n")
        else:
            docker_file.write("CMD /setup_files/move_ds.bash " + name_server[
                "zone"] + " && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && cd / && ./qbf/daemon ${LISTENIP} --maxudp " + str(
                maxudp) + " & named -d 3 && /bin/bash\n")
    else:
        if zone == ".":
            zone = "root"
            out = "."
        else:
            zone = name_server["zone"][:-1]
            out = zone
        docker_file.write("ARG SIGN=unknown\n")
        docker_file.write("RUN echo $SIGN\n")
        cmd_str = "CMD cd /usr/local/etc/bind/zones "
        for c_zone in name_server["child_zones"]:
            cmd_str += "&& /setup_files/add_ds.bash " + name_server["file"] + " " + c_zone + " "
        if BYPASS:
            cmd_str += "&& if [ ! -f /usr/local/etc/bind/zones/" + name_server[
                "file"] + ".signed ]; then dnssec-signzone -o " + out + " -N INCREMENT -t -S -K /usr/local/etc/bind/zones db." + zone + ";fi && /setup_files/move_ds.bash . && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && cd / && ./qbf/daemon ${LISTENIP} --bypass & named -g -d 3\n"
        else:
            cmd_str += "&& if [ ! -f /usr/local/etc/bind/zones/" + name_server[
                "file"] + ".signed ]; then dnssec-signzone -o " + out + " -N INCREMENT -t -S -K /usr/local/etc/bind/zones db." + zone + ";fi && /setup_files/move_ds.bash . && iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 && iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 && ifconfig && cd / && ./qbf/daemon ${LISTENIP} --maxudp " + str(
                maxudp) + " & named -g -d 3\n"
        docker_file.write(cmd_str)
    docker_file.close()
    docker_compose_file.write("        build:\n")
    docker_compose_file.write("            context: " + name_server["name"] + "/\n")
    docker_compose_file.write("            args:\n")
    docker_compose_file.write("                LISTENIP: " + name_server["networks"][0]["ip_address"] + "\n")
    docker_compose_file.write("        stdin_open: true\n")
    docker_compose_file.write("        privileged: true\n")
    docker_compose_file.write("        tty: true\n")
    docker_compose_file.write("        networks:\n")
    for network in name_server["networks"]:
        docker_compose_file.write("            " + network["network_name"] + ":\n")
        docker_compose_file.write("                ipv4_address: " + network["ip_address"] + "\n")
    docker_compose_file.write("        volumes:\n")
    docker_compose_file.write("            - dsset-volume:/dsset\n")
    docker_compose_file.write("        cap_add:\n")
    docker_compose_file.write("           - NET_ADMIN\n")

docker_compose_file.write("volumes:\n")
docker_compose_file.write("    dsset-volume:\n")
docker_compose_file.close();

os.system("cp tmux-run-docker-part1.bash build/tmux-run-docker-part1.bash")
os.system("cp tmux-run-docker-part2.bash build/tmux-run-docker-part2.bash")
