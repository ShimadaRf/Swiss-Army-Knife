#!/bin/bash

VERDE='\e[1;32m'
VERMELHO='\e[1;31m'
AZUL='\e[1;34m'
LARANJA='\e[1;33m'
NC='\033[0m'

echo -e "${VERDE}Swiss Army Knife${NC}"
echo "Selecione o serviço:"
echo " 1. Scann - Host Discovery"
echo " 2. Scann - Portas Abertas"
echo " 3. Parsing Html"
echo " 4. Tranferencia de zona"
echo " 5. DNS Enum"
echo " 6. Sub Takeover"
echo " 7. DoS (NAO IMPLEMENTADO)"
echo " 8. Exploit (NAO IMPLEMENTADO)"
echo " 9. Brute Force (NAO IMPLEMENTADO)"
echo "------------------------------"

read -r -p "Digite a opção desejada: " SELECAO

if [[ $SELECAO -eq 1 ]]; then

    # OPÇÃO 1: HOST DISCOVERY

    echo -e "\n${VERDE}## Opção 1: Host Discovery (Ping Scan)${NC}"

    echo "Selecione o tipo de alvo para o scan:"
    echo " 1. Varredura de Faixa (Hosts de 1 a 254)"
    echo " 2. Host Específico"

    read -r -p "Digite 1 ou 2: " TIPO_VARREDURA

    if [[ $TIPO_VARREDURA -eq 1 ]]; then
        read -r -p "Digite o prefixo da rede (ex: 192.168.1): " PREFIXO

        echo -e "\n${VERDE}Executando Nmap Ping Scan na faixa: $PREFIXO.1 a $PREFIXO.254${NC}"

        for i in $(seq 1 254); do
            HOST="$PREFIXO.$i"
            nmap -sn "$HOST" | grep "Nmap scan report for" &
        done
        echo -e "\n${VERDE}Varredura de faixa concluída.${NC}"

    elif [[ $TIPO_VARREDURA -eq 2 ]]; then
        read -r -p "Digite o IP do host específico (ex: 192.168.1.100): " HOST_ESPECIFICO

        echo -e "\n${VERDE}Executando Nmap Ping Scan no host específico: $HOST_ESPECIFICO...${NC}"

        RESULTADO=$(nmap -sn "$HOST_ESPECIFICO" 2>/dev/null | grep "Host is up" | awk '{print $1, $2, $3}')

        if [[ -z $RESULTADO ]]; then
            echo -e "${VERMELHO}Host down${NC}"
        else
            echo -e "${AZUL}Status do Host: $RESULTADO${NC}"
        fi

    else
        echo -e "\n${VERMELHO}Opção de varredura inválida.${NC}"
    fi

elif [[ $SELECAO -eq 2 ]]; then

    # OPÇÃO 2: PORT SCAN

    echo -e "\n${VERDE}## Opção 2: Varredura de Portas Abertas${NC}"

    read -r -p "Digite o IP do host que deseja escanear as portas: " HOST_PORT_SCAN

    echo "Selecione o tipo de varredura:"
    echo " 1. Top 1000 Portas (Padrão e Rápido)"
    echo " 2. Todas as 65535 Portas (Lento)"

    read -r -p "Digite 1 ou 2: " TIPO_SCAN_PORTA

    if [[ $TIPO_SCAN_PORTA -eq 1 ]]; then
        echo -e "\n${AZUL}Iniciando Nmap (Top 1000 Portas) em $HOST_PORT_SCAN...${NC}"
        nmap -sV "$HOST_PORT_SCAN"

    elif [[ $TIPO_SCAN_PORTA -eq 2 ]]; then
        echo -e "\n${VERMELHO}AVISO: Este scan é muito lento!${NC}"
        echo -e "${AZUL}Iniciando Nmap (todas as portas) em $HOST_PORT_SCAN...${NC}"
        nmap -sV -p- "$HOST_PORT_SCAN"

    else
        echo -e "\n${VERMELHO}Opção de scan de porta inválida.${NC}"
    fi

elif [[ $SELECAO -eq 3 ]]; then

    # OPÇÃO 3: PARSING HTML

	echo -e "\n${VERDE}## Opção 3: Parsing HTML${NC}"

	read -r -p "Digite o endereço alvo (ex. facebook.com): " ENDERECO

	echo "Selecione o tipo de parsing"
	echo " 1. Listar todas as hrefs"
	echo " 2. Listar apenas os endereços relacionados"

	read -r -p "Digite 1 ou 2: " PARSING

	echo -e "\n${AZUL}===========================================================================${NC}"
	echo -e "\n${LARANJA}Explorando $ENDERECO${NC}"
	echo -e "\n${AZUL}===========================================================================${NC}"

	if [[ $PARSING -eq 1 ]]; then
		printf "${AZUL}%-40s %-30s\n${NC}" "IP" "DOMAIN"

		for end in $(wget -qO- $ENDERECO 2>/dev/null | grep -oE 'https?://[^"]+' | cut -d "/" -f 3 | sort -u)
		do
			ips=$(host "$end" 2>/dev/null)

			echo "$ips" | grep "has address" | awk '{print $4, $1}' | while read -r ip host; do
				printf "%-40s %-30s\n" "$ip" "$host"
			done

			echo "$ips" | grep "has IPv6" | awk '{print $5, $1}' | while read -r ip host; do
				printf "%-40s %-30s\n" "$ip" "$host"
			done
		done
		echo -e "${AZUL}============================================================================${NC}"

	elif [[ $PARSING -eq 2 ]]; then
		host_alvo=$(echo "$ENDERECO" | sed 's/https\?:\/\///' | cut -d/ -f1)
		keyword=$(echo "$host_alvo" | cut -d. -f1)

		ip_alvo=$(host "$host_alvo" | grep -m1 "has address" | awk '{print $4}')
		[ -z "$ip_alvo" ] && ip_alvo=$(host "$host_alvo" | grep -m1 "has IPv6 address" | awk '{print $5}')

		asn_alvo=$(whois -h whois.cymru.com " -v $ip_alvo" | tail -n1 | awk -F'|' '{print $1}' | tr -d ' ')

		printf "${AZUL}%-40s %-30s %-10s %-12s${NC}\n" "IP" "DOMAIN" "ASN" "VÍNCULO"

		urls=$(wget -qO- "$ENDERECO" 2>/dev/null | grep -oE 'https?://[^/"]+' | cut -d "/" -f 3 | tr -d '\r\\'  | sort -u)

		for s in $urls; do
			dns_info=$(host "$s" 2>/dev/null)

			echo "$dns_info" | grep -E "has address|has IPv6 address" | while read -r line; do
				if echo "$line" | grep -q "IPv6"; then
					ip_atual=$(echo "$line" | awk '{print $5}')
				else
					ip_atual=$(echo "$line" | awk '{print $4}')
				fi

				asn_atual=$(whois -h whois.cymru.com " -v $ip_atual" | tail -n1 | awk -F'|' '{print $1}' | tr -d ' ')

				vinculo="Desconhecido"
				cor=$NC

				if [ "$asn_atual" == "$asn_alvo" ]; then
					vinculo="ASN"
					cor=$VERDE
				elif [[ "$s" == *"$keyword"* ]]; then
					vinculo="NOME"
					cor=$LARANJA
				elif timeout 2 openssl s_client -connect "$s":443 -servername "$s" </dev/null 2>/dev/null | \
					openssl x509 -noout -text 2>/dev/null  | grep -qi "$keyword"; then
					vinculo="SSL-CERT"
					cor=$VERDE
				fi

				if [ "$vinculo" != "Desconhecido" ]; then
					printf "${cor}%-40s %-30s %-10s %-12s${NC}\n" "$ip_atual" "$s" "$asn_atual" "$vinculo"
				fi
			done
		done
		echo -e "${AZUL}============================================================================${NC}"
	fi

elif [[ $SELECAO -eq 4 ]]; then

    # OPÇÃO 4: Transferencia de Zona

	echo -e "\n${VERDE}## Opção 4: Zone Transfer${NC}"

	read -r -p "Digite o endereço alvo (ex. facebook.com): " ENDERECO

	echo -e "\n${AZUL}====================================================================${NC}"
        echo -e "\n${LARANJA}Explorando $ENDERECO${NC}"
        echo -e "\n${AZUL}====================================================================${NC}"

	echo -e "${VERMELHO}Servidores encontrados:${NC}"
	servers=$(host -t ns $ENDERECO | cut -d " " -f 4);
	echo "$servers"

	echo -e "${AZUL}====================================================================${NC}"

	for server in $servers;
	do
		host -l $ENDERECO $server;
	done

	echo -e "${AZUL}====================================================================${NC}"

elif [[ $SELECAO -eq 5 ]]; then

    # OPÇÃO 5: Dns Enum

	echo -e "\n${VERDE}## Opção 5: Dns Enum${NC}"

	read -r -p "Digite o endereço alvo (ex. facebook.com): " ENDERECO

	read -r -p "Endereço da lista: " LISTA

	echo -e "\n${AZUL}==================================================================${NC}"
	echo -e "\n${LARANJA}Explorando $ENDERECO${NC}"
	echo -e "\n${AZUL}==================================================================${NC}"

	echo -e "${VERMELHO}Serviços Encontrados: ${NC}"

	while read pref;
	do
		host $pref.$ENDERECO | grep -v "NXDOMAIN";
	done < $LISTA
	echo -e "\n${AZUL}==================================================================${NC}"

elif [[ $SELECAO -eq 6 ]]; then

    # OPÇÃO 6: Sub Takeover

        echo -e "\n${VERDE}## Opção 6: Sub Takeover${NC}"

	echo "Selecione a opção desejada"
	echo "1. Lista de Possíveis Subdomínios"
	echo "2. Lista de Endereços"
	read -r -p "Digite a opção desejada: " OPCAO

        read -r -p "Digite o endereço alvo (ex. facebook.com): " ENDERECO

        read -r -p "Endereço da lista: " LISTA

        echo -e "\n${AZUL}==================================================================${NC}"
        echo -e "\n${LARANJA}Procurando possibilidades em $ENDERECO${NC}"
        echo -e "\n${AZUL}==================================================================${NC}"
        if [[ $OPCAO -eq 1 ]]; then

		printf "${LARANJA}%-30s -------> %-30s${NC}\n" "ALIAS" "CNAME"

        	while read pref;
        	do
               		host -t cname $pref.$ENDERECO | grep "alias" | awk '{printf "%-30s -------> %-30s\n", $1, $6}';        
		done < $LISTA

        elif [[ $OPCAO -eq 2 ]]; then

		printf "${LARANJA}%-30s -------> %-30s${NC}\n" "ALIAS" "CNAME"

		while read ender;
                do
                        host -t cname $ender | grep "alias" | awk '{printf "%-30s -------> %-30s\n", $1, $6}';
                done < $LISTA


	echo -e "\n${AZUL}==================================================================${NC}"

	fi

# ------- NAO IMPLEMENTADO ------------

elif [[ $SELECAO -eq 7 ]]; then
    echo -e "\n${VERDE}## Opção 7: Exploit${NC}"
    echo "Funcionalidade de Exploit."

elif [[ $SELECAO -eq 8 ]]; then
    echo -e "\n${VERDE}## Opção 7: Exploit${NC}"
    echo "Funcionalidade de Exploit."

elif [[ $SELECAO -eq 9 ]]; then
    echo -e "\n${VERDE}## Opção 8: Brute Force${NC}"
    echo "Funcionalidade de Brute Force."

else
    echo -e "\n${VERMELHO}Opção inválida. Por favor, selecione uma opção válida.${NC}"

fi




