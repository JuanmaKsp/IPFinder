#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "IPSearch.h"

char fechayhora[100];

void insertaFinal(Pip *ips, Pip nuevo);
void actualiza(Pip *ips , Pgrupo nuevo, char *ip);
void actualizaHost(Pip *ips , char *nombre, char *grupo, char *ip);
Pip buscar(Pip ips, char *temp);
int contador(char arr[], int num, char token);
const char *eliminaCaracter(char *str, char token);
void cambiaCaracter(char *str, char src, char dst);
int cadenaUnico(char *cadena);

int main(){

    Pip listaIps;
    time_t t;
    struct tm *tm;
    char rango[20];
    int rangoOk;
    char salida[90] = "escaneos\\listaIps_";
    char tiempo[100];

    t = time(NULL);
    tm = localtime(&t);
    strftime(tiempo, 100, "%d/%m/%y-%H:%M:%S", tm);
    strftime(fechayhora, 100, "%d%m%y%H%M%S", tm);
    printf ("===========================================================================\n");
    printf ("=========================PROGRAMA ANALIZADOR DE RED========================\n");
    printf ("===========================================================================\n");
    printf("\n");
    printf("Hoy es: %s\n.", tiempo);
    printf("Introducir rango de ips a analizar: ");
    listaIps = inicializar();

    scanf("%19s", rango);
    //strcpy(rango, "192.168.1.0/24");

    printf("\nnEjecutando nmap.\n\n");
    rangoOk = nmap(&listaIps, rango);
    if (rangoOk != 0){
        printf("Fallo al ejecutar nmap");
        return EIO;
    }
    printf("\nFin de ejecucion de nmap.\n\n");

    //leerFNmap(&listaIps, "temp1.txt");

    printf("\nEjecucion de nbtstat.\n\n");
    nbtstat(&listaIps);
    //leerFNbtstat(&listaIps, "temp2.txt");
    printf("\nFin de ejecucion de nbtstat.\n\n");

    printf("\nEjecucion de arp y host.\n\n");
    arp(&listaIps);
    pcHost(&listaIps);
    strcat(salida, fechayhora);
    strcat(salida, ".txt");
    printf("%s\n", salida);
    guardarFIPSearch(listaIps, salida);
    limpiaMemoria(&listaIps);
	printf("bye!!");
	return EXIT_SUCCESS;
}

Pip inicializar(){
    return NULL;
}

int nmap(Pip *ips, char *rango){

    int val;
    char nmap[90] = "nmap\\nmap.exe -oN temp1.txt -sn ";

    strcat(rango, " > nul"); 
    strcat(nmap, rango);
    printf(nmap);
    printf("\n");
    val = system(nmap);
    if (val == 0)
        leerFNmap(ips, "temp1.txt");
    return val;
}

void nbtstat(Pip *ips){

    Pip aux = *ips;
    char maestro[] = "nbtstat -A ";
    char nbtstat[90];
    char ipnb[30];

    while(aux != NULL){
        strcpy(nbtstat, maestro);
        strcpy(ipnb, aux->DirIp);
        strcat(ipnb, " > temp2.txt"); 
        strcat(nbtstat, ipnb);
        printf(nbtstat);
        printf("\n");
        system(nbtstat);
        leerFNbtstat(ips,"temp2.txt", aux->DirIp);
        aux = aux->next;
    }
}

void arp(Pip *ips){

    char maestro[] = "arp -a > temp3.txt";

    system(maestro);
    leerFArp(ips, "temp3.txt");
}

void pcHost(Pip *ips){

    char *maestro = "ipconfig /all | findstr /C:Direcci /C:scara /C:Puerta > temp5.txt";
    printf(maestro);
    system(maestro);
    leerFIpconfig(ips, "temp5.txt");

    maestro = "systeminfo  > temp4.txt";

    printf(maestro);
    system(maestro);
    leerFHost(ips, "temp4.txt");

}

void limpiaMemoria(Pip *ips){

    Pip aux;

    system("del temp*.txt > nul"); //Descomentar esta linea para que se eliminen los archibos temporales
	while(*ips != NULL){
		aux = *ips;
		*ips = (*ips)->next;
		free(aux);
	}
}
int guardarFIPSearch(Pip ips, char *filename){

    FILE *fileN;
    int i = 0;
    if((fileN = fopen(filename, "wt")) == NULL)
        perror("FTexto: Error abriendo Ips.txt");
    else {
        while(ips != NULL){
            fprintf(fileN, "%s\t%s\t%s\t", ips->DirIp, ips->MAC, ips->fabricante);
            if(ips->nbios == 1)
                fprintf(fileN, "%s\t%s\n", ips->NombreUnico, ips->NombreGrupo);
            else
                fprintf(fileN, "\n");
            if(ips->next != NULL)
				fprintf(fileN, "\n");
			ips = ips->next;
        }
        fclose(fileN);
        i = 1;
    }
    return i; 
}

int leerFNmap(Pip *ips, char *filename){

    FILE *fileN; 
    int i = 0;
    char temp[90];
    char tempt[90];
    Pip aux = NULL;

    if((fileN = fopen(filename, "rt")) == NULL)
        perror("FTexto: El fichero temporal de nmap no se ha creado.\n");
    else {
        while(!feof(fileN)){
            fscanf(fileN, "%s", temp);
            if(contador(temp, strlen(temp), '.') == 3) {
                aux = (Pip)malloc(sizeof(Ip));
                if(aux == NULL){
                    perror("Falta memoria.\n");
                    exit(EXIT_FAILURE);
                }
                strcpy(aux->DirIp, temp);
                strcpy(aux->MAC, "");
                strcpy(aux->fabricante, "");
                aux->nbios = 0;
                aux->next = NULL;
                insertaFinal(ips, aux);
                i++;
            }
            if(contador(temp, strlen(temp), ':') == 5) {
                strcpy(aux->MAC, temp);
                fscanf(fileN, "%s", temp);
                if(contador(temp, strlen(temp), '(') && contador(temp, strlen(temp), ')')) {
                    eliminaCaracter(temp, '(');
                    eliminaCaracter(temp, ')');
                } else {
                    eliminaCaracter(temp, '(');
                    fscanf(fileN, "%s", tempt);
                    eliminaCaracter(tempt, ')');
                    strcat(temp, " ");
                    strcat(temp, tempt);
                }
                strcpy(aux->fabricante, temp);
            }
        }
        fclose(fileN);
    }
    return i;
}

int leerFNbtstat(Pip *ips, char *filename, char *ip){

    Pgrupo curr = NULL;
    Pip aux = *ips;
    FILE *fileN;
    int i = 0;
    char temp[90];
    char dato[90] = "";
    char trash[90] = "";
    char ungro[90] = "";

    if((fileN = fopen(filename, "rt")) == NULL)
        perror("FTexto: El fichero temporal de nbtstat no se ha creado.\n");
    else {
        curr = (Pgrupo)malloc(sizeof(Grupo));
        if(curr == NULL){
            perror("Falta memoria.\n");
            exit(EXIT_FAILURE);
        }
        while(!feof(fileN)){
            fscanf(fileN, "%s", temp);
            if (i == 0)
                strcpy(ungro, temp);
            if (i == 1){
                strcpy(trash, ungro);
                strcpy(ungro, temp);
            }
            if (i >= 2){
                strcpy(dato, trash);
                strcpy(trash, ungro);
                strcpy(ungro, temp);
            }
            if (cadenaUnico(ungro) == 1)
                strcpy(curr->NombreUnico, dato);
            if (strcmp(ungro, "Grupo") == 0)
                strcpy(curr->NombreGrupo, dato);
            if (strcmp(temp, "00-00-00-00-00-00")){
                free(curr);
                fclose(fileN);
                return 0;
            }
            i++;
        }
        actualiza(ips, curr, ip);
        free(curr);
        fclose(fileN);
    }
    return i;
}

int leerFHost(Pip *ips, char *filename){

    FILE *fileN; 
    int i = 0;
    char temp[90];
    char nombre[90];
    char grupo[90];

    if((fileN = fopen(filename, "rt")) == NULL)
        perror("FTexto: El fichero temporal de host no se ha creado.\n");
    else {
        while (!feof(fileN)){
            fscanf(fileN, "%s", temp);
            if (strcmp(temp, "Nombre") == 0){
                fscanf(fileN, "%s", temp);
                if (strcmp(temp, "de") == 0){
                    fscanf(fileN, "%s", temp);
                    if (strcmp(temp, "host:") == 0){
                        fscanf(fileN, "%s", temp);
                        strcpy(nombre, temp);
                    }
                }
            } else if (strcmp(temp, "Dominio:") == 0){
                fscanf(fileN, "%s", temp);
                strcpy(grupo, temp);
            } else if (strcmp(temp, "[01]:") == 0){
            //} else if (contador(temp, strlen(temp), '.') == 3){
                fscanf(fileN, "%s", temp);
                actualizaHost(ips, nombre, grupo, temp);
            }
        }
        fclose(fileN);
    }

}

int leerFArp(Pip *ips, char *filename){

    Pip aux = NULL;
    FILE *fileN; 
    int i = 0;
    char temp[90];

    if((fileN = fopen(filename, "rt")) == NULL)
        perror("FTexto: El fichero temporal de arp no se ha creado.\n");
    else {
        while (!feof(fileN)){
            fscanf(fileN, "%s", temp);
            if(contador(temp, strlen(temp), '.') == 3) {
                aux = buscar(*ips, temp);
                if(aux != NULL && aux->MAC != ""){
                    fscanf(fileN, "%s", temp);
                    cambiaCaracter(temp, '-', ':');
                    strcpy(aux->MAC, temp);
                }
            }
        }
        fclose(fileN);
    }
}

int leerFIpconfig(Pip *ips, char *filename){

    Pip aux = NULL;
    Pip curr;
    FILE *fileN; 
    int i = 0;
    char temp[90];
    char mac[90] = "";
    char direccion[90] = "";
    char *dir;
    char mascara[90] = "";
    char puerta[90] = "";

    if((fileN = fopen(filename, "rt")) == NULL)
        perror("FTexto: El fichero temporal de arp no se ha creado.\n");
    else {
        while (!feof(fileN)){
            fscanf(fileN, "%s", temp);
            if(strcmp(temp, ":") == 0){
                fscanf(fileN, "%s", temp);
                if (i == 0)
                    strcpy(puerta, temp);
                if (i == 1){
                    strcpy(mascara, puerta);
                    strcpy(puerta, temp);
                }
                if (i == 2){
                    strcpy(direccion, mascara);
                    strcpy(mascara, puerta);
                    strcpy(puerta, temp);
                }
                if (i >= 3){
                    strcpy(mac, direccion);
                    strcpy(direccion, mascara);
                    strcpy(mascara, puerta);
                    strcpy(puerta, temp);
                }
                aux = buscar(*ips, puerta);
                if (aux != NULL){
                    dir = strtok(direccion, "(");
                    aux = buscar(*ips, dir);
                    if(aux != NULL){
                        cambiaCaracter(mac, '-', ':');
                        strcpy(aux->MAC, mac);
                    } else if (aux == NULL) {
                        curr = (Pip)malloc(sizeof(Ip));
                        if(curr == NULL){
                            perror("Falta memoria.\n");
                            exit(EXIT_FAILURE);
                        }
                        cambiaCaracter(mac, '-', ':');
                        strcpy(curr->MAC, mac);
                        strcpy(curr->DirIp, dir);
                        insertaFinal(ips, curr);
                    }
                }
                i++;
            }
        }
        fclose(fileN);
    }
}

int cadenaUnico(char *cadena){

    if (strlen(cadena) == 5)
        if (cadena[1] == 'n' && cadena[2] == 'i' && cadena[3] == 'c' && cadena[4] == 'o')
            return 1;
    return 0;
}

const char *eliminaCaracter(char *str, char token) {

    int i,j;
    i = 0;
    
    while(i<strlen(str))
    {
        if (str[i] == token)
            for (j=i; j<strlen(str); j++)
                str[j]=str[j+1];
        else 
            i++;
    }
    return str;

}

int contador(char arr[], int num, char token){

   int b=0;

   for(int i=0;i<num;i++){
        if (arr[i] == token)
            b++;
        else if (arr[i] == '/')
            return 0;
        else if (arr[i]=='\0')
            break;
    }
    return b;
}

void cambiaCaracter(char *str, char src, char dst){

    for (int i=0;i<strlen(str);i++)
        if(str[i] == src)
            str[i] = dst;
}

void insertaFinal(Pip *ips, Pip nuevo){

	Pip curr;

	if(*ips == NULL)
		*ips = nuevo;
	else {
		curr = *ips;
		while(curr->next != NULL)
			curr = curr->next;
		curr->next = nuevo;
	}
}

void actualiza(Pip *ips , Pgrupo nuevo, char *ip){

    Pip curr = *ips;

    if (nuevo != NULL) {
        while(curr != NULL){
            if(strcmp(curr->DirIp, ip) == 0){
                curr->nbios = 1;
                strcpy(curr->NombreUnico, nuevo->NombreUnico);
                strcpy(curr->NombreGrupo, nuevo->NombreGrupo);
                break;
            }
            curr = curr->next;
        }
    }
}

void actualizaHost(Pip *ips , char *nombre, char *grupo, char *ip){

    Pip curr = *ips;

    while(curr != NULL){
        if(strcmp(curr->DirIp, ip) == 0){
            curr->nbios = 1;
            strcpy(curr->NombreUnico, nombre);
            strcpy(curr->NombreGrupo, grupo);
            break;
        }
        curr = curr->next;
    }
}

Pip buscar(Pip ips, char *temp){

    Pip aux = NULL;
	while(ips != NULL){
		if(strcmp(ips->DirIp, temp) == 0)
			aux = ips;
		ips = ips->next;
	}
	return aux;
}