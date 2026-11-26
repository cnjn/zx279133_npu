/* Dropbear build options for the ZX279133 lab UART image (copied to localoptions.h). */

/* Lab tools live in /debug/bin; the server runs `scp -t` through this PATH. */
#define DEFAULT_PATH "/debug/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define DEFAULT_ROOT_PATH "/debug/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* OpenSSH >= 9.0 scp speaks SFTP by default; serve it from the static sftp-server. */
#define DROPBEAR_SFTPSERVER 1
#define SFTPSERVER_PATH "/debug/libexec/sftp-server"

/* Host keys are generated at runtime under tmpfs; never baked into the image. */
#define ED25519_PRIV_FILENAME "/var/tmp/dropbear/dropbear_ed25519_host_key"
#define ECDSA_PRIV_FILENAME "/var/tmp/dropbear/dropbear_ecdsa_host_key"
#define RSA_PRIV_FILENAME "/var/tmp/dropbear/dropbear_rsa_host_key"
#define DSS_PRIV_FILENAME "/var/tmp/dropbear/dropbear_dss_host_key"
#define DROPBEAR_PIDFILE "/var/tmp/dropbear/dropbear.pid"

#define DROPBEAR_DSS 0
#define DROPBEAR_X11FWD 0
#define DO_MOTD 0
