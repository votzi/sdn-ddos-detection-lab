## Descripción de los Ataques Implementados

Este laboratorio implementa diferentes ataques de Denegación de Servicio (DoS) tradicionales y ataques específicos en entornos SDN (Software Defined Networking).

El objetivo es analizar su impacto en una arquitectura Spine-Leaf controlada por un controlador SDN (RYU), evaluando el comportamiento del plano de datos y del plano de control.

-------------------------------------------------------

## 1. ICMP Flood

## Descripción

El ICMP Flood es un ataque de denegación de servicio que consiste en enviar una gran cantidad de paquetes ICMP Echo Request (ping) hacia un host objetivo.

## Funcionamiento

Se generan miles de paquetes ICMP por segundo.

El host destino debe procesar cada solicitud.

Se incrementa el uso de CPU y ancho de banda.

Si no existen reglas de flujo preinstaladas, cada paquete puede generar un evento packet_in hacia el controlador.

## Impacto en SDN

En una red SDN, si el tráfico ICMP no tiene flujos previamente instalados, el switch enviará eventos packet_in al controlador. Esto puede incrementar la carga del plano de control y generar latencia adicional en la red.

-------------------------------------------------------

## 2. TCP SYN Flood
## Descripción

El TCP SYN Flood explota el proceso de establecimiento de conexión TCP (three-way handshake) enviando múltiples paquetes SYN sin completar la conexión.

## Funcionamiento

Se envían múltiples paquetes SYN al servidor.

El servidor responde con SYN-ACK.

El atacante no envía el ACK final.

Se acumulan conexiones en estado half-open.

Se consumen recursos de memoria y CPU del servidor.

## Impacto en SDN

Puede generar múltiples eventos packet_in si los flujos no están instalados. Además de afectar al host víctima, puede aumentar la carga del controlador y provocar degradación del servicio.

-------------------------------------------------------

## 3. UDP Flood
## Descripción

El UDP Flood consiste en enviar grandes cantidades de paquetes UDP hacia un host o puerto específico.

## Funcionamiento

Se genera tráfico UDP continuo.

El host destino intenta procesar cada paquete.

Si el puerto está cerrado, el host responde con mensajes ICMP Port Unreachable.

Se incrementa el consumo de CPU y ancho de banda.

## Impacto en SDN

Puede provocar la instalación constante de nuevos flujos si el tráfico utiliza múltiples puertos o direcciones. Esto incrementa la carga del controlador y puede generar saturación del plano de datos.

-------------------------------------------------------

## 4. Application Plane Attack (HTTP Flood)
## Descripción

El HTTP Flood es un ataque de capa 7 (Application Layer) que envía múltiples solicitudes HTTP legítimas hacia un servidor web.

## Funcionamiento

Se generan múltiples solicitudes GET o POST.

Las peticiones aparentan ser tráfico válido.

El servidor debe procesar cada solicitud.

Se consume CPU y memoria del servidor de aplicaciones.

## Impacto en SDN

Este ataque no necesariamente genera eventos packet_in si los flujos ya existen, pero afecta directamente al servidor de aplicaciones. Puede degradar el servicio sin saturar el plano de red.

-------------------------------------------------------

## 5. Controller Attack (Packet_in Flood)
## Descripción

Este ataque está dirigido específicamente al controlador SDN y busca saturar el plano de control.

## Funcionamiento

Se genera tráfico con direcciones MAC o IP nuevas constantemente.

El switch no encuentra reglas coincidentes.

El switch envía un evento packet_in al controlador por cada paquete.

El controlador debe procesar cada evento e instalar nuevos flujos.

## Impacto en SDN

Este ataque incrementa significativamente la carga del controlador. Puede generar alta utilización de CPU, retrasos en la instalación de flujos y, en casos extremos, la caída del plano de control.

Es uno de los ataques más críticos en arquitecturas SDN, ya que explota directamente la separación entre el plano de datos y el plano de control.

-------------------------------------------------------

## 6. Communication Link Attack
## Descripción

El Communication Link Attack busca saturar los enlaces físicos o lógicos dentro de la red, como enlaces entre switches o entre switch y controlador.

## Funcionamiento

Se genera tráfico masivo entre segmentos específicos de la red.

Se congestiona el enlace troncal.

Se incrementa la latencia.

Puede haber pérdida de paquetes.

## Impacto en SDN

Puede afectar simultáneamente múltiples hosts y servicios. También puede aumentar el tiempo de instalación de flujos y provocar timeouts o degradación general del rendimiento de la red.

-------------------------------------------------------

## Conclusión General

Los ataques tradicionales (ICMP, TCP SYN y UDP Flood) afectan principalmente el plano de datos y los recursos de los hosts destino. En cambio, los ataques específicos de SDN (Packet_in Flood y Communication Link Attack) pueden comprometer directamente el plano de control y la estabilidad global de la red.

## Este laboratorio permite analizar:

1. Consumo de CPU en hosts y controlador

2. Generación e instalación de flujos

3. Saturación del plano de control

4. Impacto en latencia y conectividad