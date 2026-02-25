## El siguiente documento contiene el paso a paso para ejecutar los ataques dentro de mininet

-------------------------------------------------------

## ICMP FLOOD

## 1. Verificar que no haya contenedores activos
docker ps
docker compose down

## 2. Levantar entorno
docker compose up -d

## 3. Entrar a Mininet
docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 4. En otra terminal entrar al contenedor
docker compose exec -it mininet bash

Instalar hping si no está:

apt update
apt install -y hping3

## 5. Volver a Mininet (terminal principal)

## 6. Lanzar el ataque
h1 hping3 -1 --flood 10.1.1.2

Dejar correr mínimo 15 segundos para que el controlador registre estadísticas.

detener el ataque con ctrl + c

## 7.Bajar contenedores
docker compose down

-------------------------------------------------------

## TCP SYN FLOOD

## 1. Verificar que no haya contenedores activos

docker ps
docker compose down

## 2. Levantar el entorno

docker compose up -d

## 3. Iniciar la topología en Mininet

docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 4. En otra terminal, entrar al contenedor Mininet
docker compose exec -it mininet bash

Instalar hping3 si no está instalado:

apt update
apt install -y hping3

## 5. Volver a la terminal principal de Mininet, para levantar servidor en el host víctima (h2):


h2 iperf -s &

## 6. Lanzar el ataque desde h1

h1 hping3 -S -p 5001 --flood 10.1.1.2

Luego detenemos el ataque con Ctrl + C

## 7. Bajar contenedores

docker compose down

-------------------------------------------------------

## UDP FLOOD

## 1. Verificar contenedores

docker ps
docker compose down

## 2. Levantar entorno

docker compose up -d

## 3.Entrar a Mininet

docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 4. En otra terminal entrar al contenedor

docker compose exec -it mininet bash

## 5. Instalar herramientas si es necesario:

apt update
apt install -y hping3 iperf

## 6. Volver a Mininet

Levantar servidor UDP en h2:

h2 iperf -s -u &

## 7. Lanzar ataque UDP

h1 hping3 --udp -p 5001 --flood 10.1.1.2

Dejar mínimo 15 segundos.

DETENER ATAQUE CON CTRL + C

## 8. Bajar contenedores

docker compose down

-------------------------------------------------------

## APPLICATION PLANE ATTACK (HTTP FLOOD)

## 1. Verificar contenedores

docker ps
docker compose down

## 2. Levantar entorno

docker compose up -d

## 3. Entrar a Mininet

docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 4.En otra terminal entrar al contenedor

docker compose exec -it mininet bash

Instalar herramientas:

apt update
apt install -y apache2-utils

## 5. Volver a Mininet

Levantar servidor HTTP en h2:

h2 python3 -m http.server 80 &

## 6. Lanzar HTTP Flood

h1 ab -n 100000 -c 200 http://10.1.1.2/

detener ataque ctrl + c

## 7. Bajar contenedores

docker compose down

-------------------------------------------------------

## CONTROLLER ATTACK (Packet_in Flood)

## 1 Preparación igual a las anteriores 
docker ps
docker compose down
docker compose up -d
docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 2. Entrar al contenedor (si no está hping instalado)

docker compose exec -it mininet bash
apt update
apt install -y hping3

## 3. Volver a Mininet (terminal anterior)

## 4. Lanzar ataque con IPs aleatorias

h1 hping3 -S --flood --rand-source -p 5001 10.1.1.2

Esto genera miles de packet_in hacia Ryu.

Detener ataque ctrl + c

## 5 Cerrar
docker compose down

-------------------------------------------------------

## CONTROLLER ATTACK (Packet_in Flood)

## 1. Preparación como los anteriores

docker ps
docker compose down
docker compose up -d
docker compose exec -it mininet ./scripts/mn_spineleaf_topo.py scripts/network_config.yaml

## 2. Desde Mininet lanzar ataque cross-leaf

h1 hping3 --udp --flood -p 5001 10.1.1.3

Aquí el tráfico pasa por:
s21 → s11/s12 → s22

## 3. Cerrar
docker compose down

-------------------------------------------------------