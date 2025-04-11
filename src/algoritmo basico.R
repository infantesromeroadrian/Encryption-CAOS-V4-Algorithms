# Función hash básica en R
basic_hash <- function(input_string, table_size = 256) {
  hash_value <- 0
  
  for (i in seq_along(strsplit(input_string, NULL)[[1]])) {
    char <- strsplit(input_string, NULL)[[1]][i]
    ascii <- utf8ToInt(char)
    # Algoritmo simple: combina posición, valor ASCII y suma acumulada
    hash_value <- (hash_value * 31 + ascii) %% table_size
  }
  
  return(hash_value)
}

# Probar el algoritmo con ejemplos
cat("Hash de 'Hola':", basic_hash("Hola"), "\n")
cat("Hash de 'Mundo':", basic_hash("Mundo"), "\n")
cat("Hash de 'hola' (con minúscula):", basic_hash("hola"), "\n")


# ASCII: codigo americano estandar de intercambio de informacion
# el cual le asigna a una letra un numero

#El código convierte cada letra en número.

#Mezcla esos números con una fórmula.

#Devuelve un número único para ese texto (dentro del rango 0-255).

#Sirve para representar textos de forma compacta, y comparar si dos textos son iguales sin leer letra por letra.

