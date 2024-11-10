cmake_minimum_required(VERSION 3.5.0)
project(HEPowerConsumption VERSION 0.1.0 LANGUAGES C CXX)

add_executable(HEPowerConsumption main.cpp)

set(CMAKE_BUILD_TYPE Debug)

find_package(SEAL)
target_link_libraries(HEPowerConsumption SEAL::seal)
find_package(OpenSSL REQUIRED)
target_link_libraries(HEPowerConsumption OpenSSL::SSL)
include_directories("/usr/local/include/cryptopp")
link_directories("/usr/local/lib")
target_link_libraries(HEPowerConsumption cryptopp)


# GMP (Gestione corretta dell'include e della libreria)
set(GMP_INCLUDE_DIR "/usr/include/x86_64-linux-gnu")  # Aggiorna questo percorso se necessario
set(GMP_LIBRARY "/usr/lib/x86_64-linux-gnu/libgmp.a")  # Aggiorna questo percorso se necessario

include_directories(${GMP_INCLUDE_DIR})  # Include la directory
#target_link_libraries(HEPowerConsumption ${GMP_LIBRARY})  # Collega la libreria

# Paillier (Correzione nel percorso include e libreria)
set(PAILLIER_INCLUDE_DIR "/usr/local/include")  # Directory contenente paillier.h
set(PAILLIER_LIBRARY "/usr/local/lib/libpaillier.a")  # Libreria statica Paillier

include_directories(${PAILLIER_INCLUDE_DIR})  # Include la directory
target_link_libraries(HEPowerConsumption ${PAILLIER_LIBRARY} ${GMP_LIBRARY})  # Collega la libreria Paillier
