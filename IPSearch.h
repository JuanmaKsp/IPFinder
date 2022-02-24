typedef struct ip *Pip;

typedef struct ip{ // Es el nodo de la lista
  char DirIp[90]; // Direccion IP
  char MAC[90]; // Direccion MAC
  char fabricante[90]; // Empresa dueña de la NIC
  short nbios; 
  char NombreUnico[90]; // Nombre del equipo
  char NombreGrupo[90]; // Nombre del grupod de trabajo
  Pip next;   //puntero a la siguiente IP
} Ip;

typedef struct grupo *Pgrupo;

typedef struct grupo{
    char ip[90];
    char NombreGrupo[90];
    char NombreUnico[90];
} Grupo;

Pip inicializar();
int nmap(Pip *ips, char *rango);
void nbtstat(Pip *ips);
void pcHost(Pip *ips);
void arp(Pip *ips);
void limpiaMemoria(Pip *ips);
int guardarFIPSearch(Pip ips, char *filename);
int leerFNmap(Pip *ips, char *filename);
int leerFNbtstat(Pip *ips, char *filename, char *ip);
int leerFHost(Pip *ips, char *filename);
int leerFArp(Pip * ips, char *filename);
int leerFIpconfig(Pip *ips, char *filename);